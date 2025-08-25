import { render, screen, waitFor } from '@/__tests__/test-utils'
import userEvent from '@testing-library/user-event'
import { PathSimulator } from '@/components/features/simulation/path-simulator'
import { FeedbackForm } from '@/components/features/feedback/feedback-form'
import { server } from '@/mocks/server'
import { http, HttpResponse } from 'msw'

describe('Simulation Workflow Integration', () => {
  it('completes full simulation and feedback workflow', async () => {
    const user = userEvent.setup()
    
    // Render both components to simulate the workflow
    const { rerender } = render(
      <div>
        <PathSimulator />
        <FeedbackForm />
      </div>
    )
    
    // Step 1: Run a simulation
    const techniqueInput = screen.getByLabelText(/starting technique/i)
    await user.type(techniqueInput, 'T1055')
    
    const runButton = screen.getByRole('button', { name: /run simulation/i })
    await user.click(runButton)
    
    // Verify simulation results appear
    await waitFor(() => {
      expect(screen.getByText(/simulation sim-test-123/i)).toBeInTheDocument()
      expect(screen.getByText(/process injection/i)).toBeInTheDocument()
    })
    
    // Step 2: Provide feedback on the simulation
    const feedbackTextarea = screen.getByPlaceholderText(/provide your feedback/i)
    await user.type(feedbackTextarea, 'The simulation results look accurate')
    
    // Rate the simulation
    const ratingSelect = screen.getByLabelText(/overall rating/i)
    await user.click(ratingSelect)
    await user.click(screen.getByText('4'))
    
    // Submit feedback
    const submitFeedbackButton = screen.getByRole('button', { name: /submit feedback/i })
    await user.click(submitFeedbackButton)
    
    // Verify feedback was submitted
    await waitFor(() => {
      expect(screen.getByText(/feedback submitted successfully/i)).toBeInTheDocument()
    })
  })

  it('handles errors in the workflow gracefully', async () => {
    const user = userEvent.setup()
    
    // Mock simulation failure
    server.use(
      http.post('*/v1/simulation/paths', () => {
        return HttpResponse.json(
          { error: 'Simulation service unavailable' },
          { status: 503 }
        )
      })
    )
    
    render(<PathSimulator />)
    
    const techniqueInput = screen.getByLabelText(/starting technique/i)
    await user.type(techniqueInput, 'T1055')
    
    const runButton = screen.getByRole('button', { name: /run simulation/i })
    await user.click(runButton)
    
    // Verify error message appears
    await waitFor(() => {
      expect(screen.getByText(/failed to run simulation/i)).toBeInTheDocument()
    })
    
    // User should still be able to retry
    server.use(
      http.post('*/v1/simulation/paths', async ({ request }) => {
        const body = await request.json()
        return HttpResponse.json({
          simulation_id: 'sim-retry-123',
          request: body,
          paths: [],
          summary: { paths_returned: 0 },
        })
      })
    )
    
    await user.click(runButton)
    
    await waitFor(() => {
      expect(screen.getByText(/simulation sim-retry-123/i)).toBeInTheDocument()
    })
  })
})