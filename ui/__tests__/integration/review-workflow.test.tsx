import { render, screen, waitFor } from '@/__tests__/test-utils'
import userEvent from '@testing-library/user-event'
import { ReviewQueue } from '@/components/features/active-learning/review-queue'
import { server } from '@/mocks/server'
import { http, HttpResponse } from 'msw'

describe('Review Workflow Integration', () => {
  it('completes full review workflow with multiple items', async () => {
    const user = userEvent.setup()
    
    // Track review decisions
    const reviewDecisions: any[] = []
    
    server.use(
      http.post('*/v1/active-learning/review', async ({ request }) => {
        const body = await request.json()
        reviewDecisions.push(body)
        return HttpResponse.json({
          success: true,
          message: 'Review decision recorded',
        })
      })
    )
    
    render(<ReviewQueue />)
    
    // Wait for queue to load
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
      expect(screen.getByText(/mapping/i)).toBeInTheDocument()
    })
    
    // Review first item (approve)
    const approveButtons = screen.getAllByRole('button', { name: /approve/i })
    await user.click(approveButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText(/review decision recorded/i)).toBeInTheDocument()
    })
    
    // Review second item (reject with feedback)
    const rejectButtons = screen.getAllByRole('button', { name: /reject/i })
    await user.click(rejectButtons[1])
    
    // Provide feedback for rejection
    const feedbackInput = await screen.findByPlaceholderText(/provide feedback/i)
    await user.type(feedbackInput, 'Incorrect mapping confidence')
    
    const submitButton = screen.getByRole('button', { name: /submit/i })
    await user.click(submitButton)
    
    await waitFor(() => {
      expect(reviewDecisions).toHaveLength(2)
      expect(reviewDecisions[0].decision).toBe('approved')
      expect(reviewDecisions[1].decision).toBe('rejected')
      expect(reviewDecisions[1].feedback).toContain('Incorrect mapping')
    })
  })

  it('handles queue refresh after reviews', async () => {
    const user = userEvent.setup()
    
    let queueCallCount = 0
    server.use(
      http.get('*/v1/active-learning/queue', () => {
        queueCallCount++
        
        // Return different results on subsequent calls
        if (queueCallCount === 1) {
          return HttpResponse.json([
            {
              queue_id: 'queue-1',
              item_type: 'flow_edge',
              confidence: 0.45,
              status: 'pending',
            },
          ])
        } else {
          return HttpResponse.json([
            {
              queue_id: 'queue-2',
              item_type: 'mapping',
              confidence: 0.60,
              status: 'pending',
            },
          ])
        }
      })
    )
    
    render(<ReviewQueue />)
    
    // Initial load
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
    
    // Approve the item
    const approveButton = screen.getByRole('button', { name: /approve/i })
    await user.click(approveButton)
    
    await waitFor(() => {
      expect(screen.getByText(/review decision recorded/i)).toBeInTheDocument()
    })
    
    // Refresh the queue
    const refreshButton = screen.getByRole('button', { name: /refresh/i })
    await user.click(refreshButton)
    
    // Should show new items
    await waitFor(() => {
      expect(screen.queryByText(/flow_edge/i)).not.toBeInTheDocument()
      expect(screen.getByText(/mapping/i)).toBeInTheDocument()
    })
    
    expect(queueCallCount).toBe(2)
  })

  it('handles concurrent reviews', async () => {
    const user = userEvent.setup()
    
    const reviewPromises: Promise<any>[] = []
    
    server.use(
      http.post('*/v1/active-learning/review', async ({ request }) => {
        const promise = new Promise(resolve => {
          setTimeout(() => {
            resolve(HttpResponse.json({
              success: true,
              message: 'Review decision recorded',
            }))
          }, 100)
        })
        reviewPromises.push(promise)
        return promise
      })
    )
    
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
    
    // Click multiple approve buttons quickly
    const approveButtons = screen.getAllByRole('button', { name: /approve/i })
    
    // Don't await these clicks to simulate concurrent actions
    const click1 = user.click(approveButtons[0])
    const click2 = user.click(approveButtons[1])
    
    // Wait for both to complete
    await Promise.all([click1, click2])
    
    // Both reviews should be processed
    await waitFor(() => {
      expect(reviewPromises).toHaveLength(2)
    })
  })

  it('filters and reviews specific item types', async () => {
    const user = userEvent.setup()
    
    render(<ReviewQueue />)
    
    // Wait for initial load
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
      expect(screen.getByText(/mapping/i)).toBeInTheDocument()
    })
    
    // Filter to show only flow_edge items
    const filterSelect = screen.getByLabelText(/filter by type/i)
    await user.click(filterSelect)
    await user.click(screen.getByText(/flow edge/i))
    
    // Should only show flow_edge items
    await waitFor(() => {
      expect(screen.getByText(/t1055/i)).toBeInTheDocument()
      expect(screen.queryByText(/process hollowing/i)).not.toBeInTheDocument()
    })
    
    // Review the filtered item
    const approveButton = screen.getByRole('button', { name: /approve/i })
    await user.click(approveButton)
    
    await waitFor(() => {
      expect(screen.getByText(/review decision recorded/i)).toBeInTheDocument()
    })
  })
})