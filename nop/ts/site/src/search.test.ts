// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initSearchOverlay } from './search'

function setupDom() {
  document.body.innerHTML = `
    <input id="outside-input" type="text" />
    <video id="outside-video"></video>
    <audio id="outside-audio"></audio>
    <textarea id="outside-textarea"></textarea>
    <select id="outside-select"><option>One</option></select>
    <button type="button" class="site-search-trigger site-search-trigger--mobile" data-site-search-button aria-label="Search">Search mobile</button>
    <button type="button" class="site-search-trigger site-search-trigger--desktop" data-site-search-button aria-label="Search">Search desktop</button>
    <div data-site-search-overlay hidden>
      <div data-site-search-backdrop></div>
      <section data-site-search-panel>
        <button type="button" data-site-search-close>Close</button>
        <input data-site-search-input type="text" maxlength="256" />
        <div data-site-search-status></div>
        <div data-site-search-results></div>
      </section>
    </div>
  `
}

async function flushAsync() {
  await Promise.resolve()
  await Promise.resolve()
}

describe('search overlay', () => {
  let controller: ReturnType<typeof initSearchOverlay> = null

  beforeEach(() => {
    setupDom()
    vi.useFakeTimers()
    document.body.style.overflow = ''
    controller = null
  })

  afterEach(() => {
    controller?.destroy()
    vi.useRealTimers()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('does not request or render empty state below threshold', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => []
    })
    vi.stubGlobal('fetch', fetchMock)

    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('[data-site-search-button]')!
    const input = document.querySelector<HTMLInputElement>('[data-site-search-input]')!
    const status = document.querySelector<HTMLElement>('[data-site-search-status]')!

    button.click()
    input.value = 'ab'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(300)
    await flushAsync()

    expect(fetchMock).not.toHaveBeenCalled()
    expect(status.textContent).toBe('')
    expect(status.textContent).not.toContain('No results')
  })

  it('renders no-results only for completed queries at threshold or above', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => []
    })
    vi.stubGlobal('fetch', fetchMock)

    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('[data-site-search-button]')!
    const input = document.querySelector<HTMLInputElement>('[data-site-search-input]')!
    const status = document.querySelector<HTMLElement>('[data-site-search-status]')!

    button.click()
    input.value = 'abc'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(status.textContent).toBe('No results')

    input.value = 'ab'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()
    expect(status.textContent).toBe('')
  })

  it('shows error state and logs to console on request failure', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('network'))
    vi.stubGlobal('fetch', fetchMock)
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('[data-site-search-button]')!
    const input = document.querySelector<HTMLInputElement>('[data-site-search-input]')!
    const status = document.querySelector<HTMLElement>('[data-site-search-status]')!

    button.click()
    input.value = 'abc'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()

    expect(status.textContent).toBe("Search didn't work.")
    expect(consoleSpy).toHaveBeenCalled()
  })

  it('clamps overlong query input before request dispatch', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => []
    })
    vi.stubGlobal('fetch', fetchMock)

    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('[data-site-search-button]')!
    const input = document.querySelector<HTMLInputElement>('[data-site-search-input]')!
    const query = 'x'.repeat(300)

    button.click()
    input.value = query
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url).toBe(`/api/search?q=${encodeURIComponent('x'.repeat(256))}`)
    expect(input.value).toHaveLength(256)
  })

  it('preserves leading and trailing whitespace in the input field', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => []
    })
    vi.stubGlobal('fetch', fetchMock)

    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('[data-site-search-button]')!
    const input = document.querySelector<HTMLInputElement>('[data-site-search-input]')!

    button.click()
    input.value = 'abc '
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()

    expect(input.value).toBe('abc ')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [trailingUrl] = fetchMock.mock.calls[0] as [string]
    expect(trailingUrl).toBe(`/api/search?q=${encodeURIComponent('abc')}`)

    fetchMock.mockClear()
    input.value = '  hello world '
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()

    expect(input.value).toBe('  hello world ')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [innerUrl] = fetchMock.mock.calls[0] as [string]
    expect(innerUrl).toBe(`/api/search?q=${encodeURIComponent('hello world')}`)
  })

  it('supports wrap-around keyboard selection and enter navigation', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [
        { id: '0000000000000001', alias: 'docs/alpha', title: 'Alpha' },
        { id: '0000000000000002', alias: '', title: 'Beta' }
      ]
    })
    vi.stubGlobal('fetch', fetchMock)
    const navigateSpy = vi.fn()
    ;(window as Window & typeof globalThis & { __nopSiteNavigate?: (path: string) => void }).__nopSiteNavigate =
      navigateSpy

    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('[data-site-search-button]')!
    const input = document.querySelector<HTMLInputElement>('[data-site-search-input]')!

    button.click()
    input.value = 'alpha'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    expect(document.querySelectorAll('.site-search-result.is-active')).toHaveLength(1)
    expect(document.querySelector('.site-search-result.is-active')?.textContent).toContain('Alpha')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    expect(document.querySelector('.site-search-result.is-active')?.textContent).toContain('Beta')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    expect(document.querySelector('.site-search-result.is-active')?.textContent).toContain('Alpha')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowUp', bubbles: true }))
    expect(document.querySelector('.site-search-result.is-active')?.textContent).toContain('Beta')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    expect(navigateSpy).toHaveBeenCalledWith('/id/0000000000000002')
  })

  it('keeps keyboard selection until mouse movement switches active item', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [
        { id: '0000000000000001', alias: 'docs/alpha', title: 'Alpha' },
        { id: '0000000000000002', alias: '', title: 'Beta' }
      ]
    })
    vi.stubGlobal('fetch', fetchMock)
    const navigateSpy = vi.fn()
    ;(window as Window & typeof globalThis & { __nopSiteNavigate?: (path: string) => void }).__nopSiteNavigate =
      navigateSpy

    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('.site-search-trigger--desktop')!
    const input = document.querySelector<HTMLInputElement>('[data-site-search-input]')!
    const overlay = document.querySelector<HTMLElement>('[data-site-search-overlay]')!

    button.click()
    input.value = 'alpha'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    vi.advanceTimersByTime(250)
    await flushAsync()

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    expect(overlay.classList.contains('is-keyboard-nav')).toBe(true)
    expect(document.querySelector('.site-search-result.is-active')?.textContent).toContain('Alpha')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    expect(navigateSpy).toHaveBeenCalledWith('/docs/alpha')

    navigateSpy.mockReset()
    const second = document.querySelectorAll<HTMLButtonElement>('[data-site-search-result-index]')[1]!
    second.dispatchEvent(new MouseEvent('mousemove', { bubbles: true }))
    expect(overlay.classList.contains('is-keyboard-nav')).toBe(false)
    expect(document.querySelector('.site-search-result.is-active')?.textContent).toContain('Beta')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    expect(navigateSpy).toHaveBeenCalledWith('/id/0000000000000002')
  })

  it('applies passive typing guard for editable targets', () => {
    controller = initSearchOverlay(document)
    const overlay = document.querySelector<HTMLElement>('[data-site-search-overlay]')!
    const outsideInput = document.querySelector<HTMLInputElement>('#outside-input')!
    const outsideVideo = document.querySelector<HTMLVideoElement>('#outside-video')!
    const outsideAudio = document.querySelector<HTMLAudioElement>('#outside-audio')!
    const searchInput = document.querySelector<HTMLInputElement>('[data-site-search-input]')!

    outsideInput.dispatchEvent(new KeyboardEvent('keydown', { key: 's', bubbles: true }))
    expect(overlay.hidden).toBe(true)

    outsideVideo.dispatchEvent(new KeyboardEvent('keydown', { key: 's', bubbles: true }))
    expect(overlay.hidden).toBe(true)

    outsideAudio.dispatchEvent(new KeyboardEvent('keydown', { key: 's', bubbles: true }))
    expect(overlay.hidden).toBe(true)

    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 's', bubbles: true }))
    expect(overlay.hidden).toBe(false)
    expect(searchInput.value).toBe('s')
  })

  it('opens on slash even when focused on media elements', () => {
    controller = initSearchOverlay(document)
    const overlay = document.querySelector<HTMLElement>('[data-site-search-overlay]')!
    const outsideVideo = document.querySelector<HTMLVideoElement>('#outside-video')!
    const outsideAudio = document.querySelector<HTMLAudioElement>('#outside-audio')!
    const searchInput = document.querySelector<HTMLInputElement>('[data-site-search-input]')!

    outsideVideo.dispatchEvent(new KeyboardEvent('keydown', { key: '/', bubbles: true }))
    expect(overlay.hidden).toBe(false)
    expect(searchInput.value).toBe('')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    vi.advanceTimersByTime(200)
    expect(overlay.hidden).toBe(true)

    outsideAudio.dispatchEvent(new KeyboardEvent('keydown', { key: '/', bubbles: true }))
    expect(overlay.hidden).toBe(false)
  })

  it('opens on control or command slash anywhere', () => {
    controller = initSearchOverlay(document)
    const overlay = document.querySelector<HTMLElement>('[data-site-search-overlay]')!
    const outsideInput = document.querySelector<HTMLInputElement>('#outside-input')!
    const outsideTextarea = document.querySelector<HTMLTextAreaElement>('#outside-textarea')!
    const outsideSelect = document.querySelector<HTMLSelectElement>('#outside-select')!

    outsideInput.dispatchEvent(
      new KeyboardEvent('keydown', { key: '/', ctrlKey: true, bubbles: true })
    )
    expect(overlay.hidden).toBe(false)

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    vi.advanceTimersByTime(200)
    expect(overlay.hidden).toBe(true)

    outsideTextarea.dispatchEvent(
      new KeyboardEvent('keydown', { key: '/', metaKey: true, bubbles: true })
    )
    expect(overlay.hidden).toBe(false)

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    vi.advanceTimersByTime(200)
    expect(overlay.hidden).toBe(true)

    outsideSelect.dispatchEvent(
      new KeyboardEvent('keydown', { key: '/', ctrlKey: true, bubbles: true })
    )
    expect(overlay.hidden).toBe(false)
  })

  it('closes on escape and restores body scroll', () => {
    controller = initSearchOverlay(document)
    const button = document.querySelector<HTMLElement>('[data-site-search-button]')!
    const overlay = document.querySelector<HTMLElement>('[data-site-search-overlay]')!

    expect(document.body.style.overflow).toBe('')
    button.click()
    expect(overlay.hidden).toBe(false)
    expect(document.body.style.overflow).toBe('hidden')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    vi.advanceTimersByTime(200)
    expect(overlay.hidden).toBe(true)
    expect(document.body.style.overflow).toBe('')
  })
})
