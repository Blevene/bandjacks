// Learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom'
import 'whatwg-fetch'

// Polyfills for Node.js environment
const { TextEncoder, TextDecoder } = require('util')
global.TextEncoder = TextEncoder
global.TextDecoder = TextDecoder

// Add fetch polyfill for Node.js
if (!global.fetch) {
  const { default: fetch, Request, Response, Headers } = require('whatwg-fetch')
  global.fetch = fetch
  global.Request = Request
  global.Response = Response
  global.Headers = Headers
}

const { server } = require('./mocks/server')

// Establish API mocking before all tests.
beforeAll(() => server.listen())

// Reset any request handlers that we may add during the tests,
// so they don't affect other tests.
afterEach(() => server.resetHandlers())

// Clean up after the tests are finished.
afterAll(() => server.close())

// Mock matchMedia for next-themes
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
})

// Mock pointer capture methods for Radix UI
if (typeof Element !== 'undefined') {
  Element.prototype.hasPointerCapture = Element.prototype.hasPointerCapture || jest.fn()
  Element.prototype.setPointerCapture = Element.prototype.setPointerCapture || jest.fn()
  Element.prototype.releasePointerCapture = Element.prototype.releasePointerCapture || jest.fn()
}

// Mock next/navigation
jest.mock('next/navigation', () => ({
  useRouter() {
    return {
      push: jest.fn(),
      replace: jest.fn(),
      prefetch: jest.fn(),
      back: jest.fn(),
      pathname: '/',
      query: {},
      asPath: '/',
    }
  },
  useSearchParams() {
    return {
      get: jest.fn(),
    }
  },
  usePathname() {
    return '/'
  },
  useParams() {
    return {}
  },
}))

// Mock environment variables
process.env.NEXT_PUBLIC_API_URL = 'http://localhost:8000'

// Silence console errors during tests unless explicitly testing error scenarios
const originalError = console.error
beforeAll(() => {
  console.error = jest.fn()
})

afterAll(() => {
  console.error = originalError
})