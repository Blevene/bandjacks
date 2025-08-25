import { render, screen, waitFor } from '@/__tests__/test-utils'
import userEvent from '@testing-library/user-event'
import { ReportUploader } from '@/components/features/ingestion/report-uploader'
import { createMockFile } from '@/__tests__/test-utils'
import { server } from '@/mocks/server'
import { http, HttpResponse } from 'msw'

describe('ReportUploader', () => {
  it('renders all upload methods', () => {
    render(<ReportUploader />)
    
    expect(screen.getByRole('tab', { name: /file upload/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /url/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /text/i })).toBeInTheDocument()
  })

  it('handles file upload successfully', async () => {
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    const file = createMockFile('report.pdf', 1024, 'application/pdf')
    const input = screen.getByLabelText(/drag.*drop.*files/i)
    
    await user.upload(input, file)
    
    await waitFor(() => {
      expect(screen.getByText('report.pdf')).toBeInTheDocument()
    })
    
    const uploadButton = screen.getByRole('button', { name: /upload/i })
    await user.click(uploadButton)
    
    await waitFor(() => {
      expect(screen.getByText(/successfully ingested report/i)).toBeInTheDocument()
      expect(screen.getByText(/techniques: 2/i)).toBeInTheDocument()
    })
  })

  it('validates file types', async () => {
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    const file = createMockFile('invalid.exe', 1024, 'application/x-msdownload')
    const input = screen.getByLabelText(/drag.*drop.*files/i)
    
    await user.upload(input, file)
    
    await waitFor(() => {
      expect(screen.getByText(/invalid file type/i)).toBeInTheDocument()
    })
  })

  it('handles URL ingestion', async () => {
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    // Switch to URL tab
    const urlTab = screen.getByRole('tab', { name: /url/i })
    await user.click(urlTab)
    
    const urlInput = screen.getByPlaceholderText(/https:\/\/example.com/i)
    await user.type(urlInput, 'https://example.com/report.pdf')
    
    const ingestButton = screen.getByRole('button', { name: /ingest from url/i })
    await user.click(ingestButton)
    
    await waitFor(() => {
      expect(screen.getByText(/successfully ingested report/i)).toBeInTheDocument()
    })
  })

  it('validates URL format', async () => {
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    const urlTab = screen.getByRole('tab', { name: /url/i })
    await user.click(urlTab)
    
    const urlInput = screen.getByPlaceholderText(/https:\/\/example.com/i)
    await user.type(urlInput, 'not-a-url')
    
    const ingestButton = screen.getByRole('button', { name: /ingest from url/i })
    await user.click(ingestButton)
    
    await waitFor(() => {
      expect(screen.getByText(/please enter a valid url/i)).toBeInTheDocument()
    })
  })

  it('handles text ingestion', async () => {
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    // Switch to text tab
    const textTab = screen.getByRole('tab', { name: /text/i })
    await user.click(textTab)
    
    const textArea = screen.getByPlaceholderText(/paste or type/i)
    await user.type(textArea, 'The attacker used process injection (T1055) followed by credential dumping.')
    
    const analyzeButton = screen.getByRole('button', { name: /analyze text/i })
    await user.click(analyzeButton)
    
    await waitFor(() => {
      expect(screen.getByText(/successfully ingested report/i)).toBeInTheDocument()
    })
  })

  it('shows progress stages during ingestion', async () => {
    server.use(
      http.post('*/v1/reports/ingest/upload', async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
        return HttpResponse.json({
          report_id: 'report-upload-123',
          techniques: ['T1055', 'T1003'],
          relationships: [],
          flow_id: 'flow-upload-123',
          status: 'success',
        })
      })
    )
    
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    const file = createMockFile('report.pdf', 1024, 'application/pdf')
    const input = screen.getByLabelText(/drag.*drop.*files/i)
    
    await user.upload(input, file)
    
    const uploadButton = screen.getByRole('button', { name: /upload/i })
    await user.click(uploadButton)
    
    // Should show progress stages
    expect(screen.getByText(/uploading/i)).toBeInTheDocument()
    
    await waitFor(() => {
      expect(screen.getByText(/extracting/i)).toBeInTheDocument()
    })
    
    await waitFor(() => {
      expect(screen.getByText(/mapping/i)).toBeInTheDocument()
    })
    
    await waitFor(() => {
      expect(screen.getByText(/successfully ingested/i)).toBeInTheDocument()
    })
  })

  it('handles ingestion errors', async () => {
    server.use(
      http.post('*/v1/reports/ingest/upload', () => {
        return new HttpResponse(null, { status: 500 })
      })
    )
    
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    const file = createMockFile('report.pdf', 1024, 'application/pdf')
    const input = screen.getByLabelText(/drag.*drop.*files/i)
    
    await user.upload(input, file)
    
    const uploadButton = screen.getByRole('button', { name: /upload/i })
    await user.click(uploadButton)
    
    await waitFor(() => {
      expect(screen.getByText(/failed to ingest report/i)).toBeInTheDocument()
    })
  })

  it('clears selected files', async () => {
    const user = userEvent.setup()
    render(<ReportUploader />)
    
    const file = createMockFile('report.pdf', 1024, 'application/pdf')
    const input = screen.getByLabelText(/drag.*drop.*files/i)
    
    await user.upload(input, file)
    
    expect(screen.getByText('report.pdf')).toBeInTheDocument()
    
    const clearButton = screen.getByRole('button', { name: /clear/i })
    await user.click(clearButton)
    
    expect(screen.queryByText('report.pdf')).not.toBeInTheDocument()
  })
})