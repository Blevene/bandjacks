import { render, screen, waitFor } from '@/__tests__/test-utils'
import userEvent from '@testing-library/user-event'
import { PathSimulator } from '@/components/features/simulation/path-simulator'

// Mock the API client
jest.mock('@/lib/api-client', () => ({
  typedApi: {
    simulation: {
      paths: jest.fn(),
    },
  },
}))

import { typedApi } from '@/lib/api-client'
const mockSimulation = typedApi.simulation as jest.Mocked<typeof typedApi.simulation>

describe('PathSimulator', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders the simulation form', () => {
    render(<PathSimulator />)
    
    expect(screen.getByRole('button', { name: /simulate/i })).toBeInTheDocument()
    expect(screen.getByDisplayValue('5')).toBeInTheDocument() // max_depth
    expect(screen.getByDisplayValue('10')).toBeInTheDocument() // num_paths
  })

  it('successfully runs a simulation', async () => {
    const mockResponse = {
      paths: [
        {
          path_id: 'path-1',
          steps: [
            { technique_id: 'T1055', technique_name: 'Process Injection' },
            { technique_id: 'T1003', technique_name: 'OS Credential Dumping' },
          ],
        },
      ],
    }
    
    mockSimulation.paths.mockResolvedValueOnce(mockResponse)
    
    const user = userEvent.setup()
    render(<PathSimulator />)
    
    // Set technique input
    const techniqueInput = screen.getByPlaceholderText(/t1055/i)
    await user.type(techniqueInput, 'T1055')
    
    const simulateButton = screen.getByRole('button', { name: /simulate/i })
    await user.click(simulateButton)
    
    await waitFor(() => {
      expect(mockSimulation.paths).toHaveBeenCalledWith(
        expect.objectContaining({
          start_technique: 'T1055',
        })
      )
    })
    
    await waitFor(() => {
      expect(screen.getByText(/process injection/i)).toBeInTheDocument()
      expect(screen.getByText(/os credential dumping/i)).toBeInTheDocument()
    })
  })

  it('handles simulation errors gracefully', async () => {
    mockSimulation.paths.mockRejectedValueOnce(new Error('Simulation failed'))
    
    const user = userEvent.setup()
    render(<PathSimulator />)
    
    const techniqueInput = screen.getByPlaceholderText(/t1055/i)
    await user.type(techniqueInput, 'T1055')
    
    const simulateButton = screen.getByRole('button', { name: /simulate/i })
    await user.click(simulateButton)
    
    await waitFor(() => {
      expect(screen.getByText(/error/i)).toBeInTheDocument()
    })
  })

  it('changes simulation parameters', async () => {
    const user = userEvent.setup()
    render(<PathSimulator />)
    
    // Change method to monte_carlo
    const methodSelect = screen.getByLabelText(/simulation method/i)
    await user.click(methodSelect)
    await user.click(screen.getByText(/monte carlo/i))
    
    // Change max depth
    const depthInput = screen.getByLabelText(/max depth/i)
    await user.clear(depthInput)
    await user.type(depthInput, '10')
    
    // Enable include sub-techniques
    const subTechCheckbox = screen.getByLabelText(/include sub-techniques/i)
    await user.click(subTechCheckbox)
    
    // Verify values are set
    expect(methodSelect).toHaveTextContent(/monte carlo/i)
    expect(depthInput).toHaveValue(10)
    expect(subTechCheckbox).toBeChecked()
  })

  it('displays loading state during simulation', async () => {
    server.use(
      http.post('*/v1/simulation/paths', async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
        return HttpResponse.json({
          simulation_id: 'sim-test-123',
          paths: [],
          summary: { paths_returned: 0 },
        })
      })
    )
    
    const user = userEvent.setup()
    render(<PathSimulator />)
    
    const input = screen.getByLabelText(/starting technique/i)
    await user.type(input, 'T1055')
    
    const submitButton = screen.getByRole('button', { name: /run simulation/i })
    await user.click(submitButton)
    
    expect(screen.getByText(/running simulation/i)).toBeInTheDocument()
    
    await waitFor(() => {
      expect(screen.queryByText(/running simulation/i)).not.toBeInTheDocument()
    })
  })
})