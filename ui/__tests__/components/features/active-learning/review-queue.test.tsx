import { render, screen, waitFor } from '@/__tests__/test-utils'
import userEvent from '@testing-library/user-event'
import { ReviewQueue } from '@/components/features/active-learning/review-queue'
import { server } from '@/mocks/server'
import { http, HttpResponse } from 'msw'

describe('ReviewQueue', () => {
  it('renders the review queue with items', async () => {
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/review queue/i)).toBeInTheDocument()
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
      expect(screen.getByText(/mapping/i)).toBeInTheDocument()
    })
  })

  it('displays queue statistics', async () => {
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/pending: 15/i)).toBeInTheDocument()
      expect(screen.getByText(/reviewed: 45/i)).toBeInTheDocument()
      expect(screen.getByText(/rejected: 5/i)).toBeInTheDocument()
    })
  })

  it('filters queue by type', async () => {
    const user = userEvent.setup()
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
    
    const filterSelect = screen.getByLabelText(/filter by type/i)
    await user.click(filterSelect)
    await user.click(screen.getByText(/flow edge/i))
    
    await waitFor(() => {
      expect(screen.getByText(/t1055/i)).toBeInTheDocument()
      expect(screen.queryByText(/process hollowing/i)).not.toBeInTheDocument()
    })
  })

  it('approves an item', async () => {
    const user = userEvent.setup()
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
    
    const approveButtons = screen.getAllByRole('button', { name: /approve/i })
    await user.click(approveButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText(/review decision recorded/i)).toBeInTheDocument()
    })
  })

  it('rejects an item with feedback', async () => {
    const user = userEvent.setup()
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
    
    const rejectButtons = screen.getAllByRole('button', { name: /reject/i })
    await user.click(rejectButtons[0])
    
    // Should show feedback dialog
    const feedbackInput = await screen.findByPlaceholderText(/provide feedback/i)
    await user.type(feedbackInput, 'Incorrect probability')
    
    const submitButton = screen.getByRole('button', { name: /submit/i })
    await user.click(submitButton)
    
    await waitFor(() => {
      expect(screen.getByText(/review decision recorded/i)).toBeInTheDocument()
    })
  })

  it('handles API errors gracefully', async () => {
    server.use(
      http.get('*/v1/active-learning/queue', () => {
        return new HttpResponse(null, { status: 500 })
      })
    )
    
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/failed to load review queue/i)).toBeInTheDocument()
    })
  })

  it('refreshes the queue', async () => {
    const user = userEvent.setup()
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
    
    const refreshButton = screen.getByRole('button', { name: /refresh/i })
    await user.click(refreshButton)
    
    // Should show loading state
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
    
    await waitFor(() => {
      expect(screen.queryByText(/loading/i)).not.toBeInTheDocument()
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
  })

  it('displays confidence scores correctly', async () => {
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/45%/)).toBeInTheDocument() // confidence: 0.45
      expect(screen.getByText(/60%/)).toBeInTheDocument() // confidence: 0.60
    })
  })

  it('shows item details when expanded', async () => {
    const user = userEvent.setup()
    render(<ReviewQueue />)
    
    await waitFor(() => {
      expect(screen.getByText(/flow_edge/i)).toBeInTheDocument()
    })
    
    const expandButtons = screen.getAllByRole('button', { name: /show details/i })
    await user.click(expandButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText(/source: t1055/i)).toBeInTheDocument()
      expect(screen.getByText(/target: t1003/i)).toBeInTheDocument()
      expect(screen.getByText(/flow_id: flow-123/i)).toBeInTheDocument()
    })
  })
})