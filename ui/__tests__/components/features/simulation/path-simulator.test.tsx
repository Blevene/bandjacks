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
    
    expect(screen.getByRole('button', { name: /run simulation/i })).toBeInTheDocument()
    expect(screen.getByDisplayValue('5')).toBeInTheDocument() // max_depth
    expect(screen.getByDisplayValue('10')).toBeInTheDocument() // num_paths
    expect(screen.getByPlaceholderText(/t1055/i)).toBeInTheDocument()
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
          complexity_score: 3.5,
          total_probability: 0.75,
          confidence_score: 0.8,
          covered_tactics: ['persistence', 'privilege-escalation'],
        },
      ],
    }
    
    mockSimulation.paths.mockResolvedValueOnce(mockResponse)
    
    const user = userEvent.setup()
    render(<PathSimulator />)
    
    // Set technique input
    const techniqueInput = screen.getByPlaceholderText(/t1055/i)
    await user.type(techniqueInput, 'T1055')
    
    const simulateButton = screen.getByRole('button', { name: /run simulation/i })
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
    
    const simulateButton = screen.getByRole('button', { name: /run simulation/i })
    await user.click(simulateButton)
    
    await waitFor(() => {
      expect(screen.getByText(/error/i)).toBeInTheDocument()
    })
  })

  it('displays loading state during simulation', async () => {
    // Create a promise we can control
    let resolveSimulation: (value: any) => void
    const simulationPromise = new Promise(resolve => {
      resolveSimulation = resolve
    })
    
    mockSimulation.paths.mockReturnValueOnce(simulationPromise)
    
    const user = userEvent.setup()
    render(<PathSimulator />)
    
    const techniqueInput = screen.getByPlaceholderText(/t1055/i)
    await user.type(techniqueInput, 'T1055')
    
    const submitButton = screen.getByRole('button', { name: /run simulation/i })
    await user.click(submitButton)
    
    // Should show loading state
    expect(screen.getByText(/simulating/i)).toBeInTheDocument()
    
    // Resolve the promise
    resolveSimulation!({ paths: [] })
    
    await waitFor(() => {
      expect(screen.queryByText(/simulating/i)).not.toBeInTheDocument()
    })
  })
})