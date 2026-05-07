// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

const SEARCH_DEBOUNCE_MS = 250
const SEARCH_OVERLAY_HIDE_MS = 180
const SEARCH_MIN_QUERY_LEN = 3
const SEARCH_MAX_QUERY_LEN = 256

const SELECTORS = {
  button: '[data-site-search-button]',
  overlay: '[data-site-search-overlay]',
  backdrop: '[data-site-search-backdrop]',
  panel: '[data-site-search-panel]',
  input: '[data-site-search-input]',
  close: '[data-site-search-close]',
  status: '[data-site-search-status]',
  results: '[data-site-search-results]'
} as const

type SearchHit = {
  id: string
  alias: string
  title: string
}

type SiteSearchWindow = Window &
  typeof globalThis & {
    __nopSiteNavigate?: (path: string) => void
  }

export type SiteSearchOverlayController = {
  destroy: () => void
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false
  }
  if (target.isContentEditable) {
    return true
  }
  const tag = target.tagName.toUpperCase()
  return (
    tag === 'INPUT' ||
    tag === 'TEXTAREA' ||
    tag === 'SELECT' ||
    tag === 'VIDEO' ||
    tag === 'AUDIO'
  )
}

function isMediaTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false
  }
  const tag = target.tagName.toUpperCase()
  return tag === 'VIDEO' || tag === 'AUDIO'
}

function isSlashShortcut(event: KeyboardEvent): boolean {
  return (
    event.key === '/' &&
    !event.ctrlKey &&
    !event.metaKey &&
    !event.altKey &&
    !event.isComposing
  )
}

function isGlobalSlashShortcut(event: KeyboardEvent): boolean {
  return (
    event.key === '/' &&
    (event.ctrlKey || event.metaKey) &&
    !event.altKey &&
    !event.isComposing
  )
}

function isPrintableCharacterKey(event: KeyboardEvent): boolean {
  return (
    event.key.length === 1 &&
    !event.ctrlKey &&
    !event.metaKey &&
    !event.altKey &&
    !event.isComposing
  )
}

function normalizeQuery(raw: string): string {
  const trimmed = raw.trim()
  if (trimmed.length > SEARCH_MAX_QUERY_LEN) {
    return trimmed.slice(0, SEARCH_MAX_QUERY_LEN)
  }
  return trimmed
}

function parseHits(payload: unknown): SearchHit[] {
  if (!Array.isArray(payload)) {
    return []
  }
  const hits: SearchHit[] = []
  for (const item of payload) {
    if (!item || typeof item !== 'object') {
      continue
    }
    const value = item as Record<string, unknown>
    if (
      typeof value.id !== 'string' ||
      typeof value.alias !== 'string' ||
      typeof value.title !== 'string'
    ) {
      continue
    }
    hits.push({
      id: value.id,
      alias: value.alias,
      title: value.title
    })
  }
  return hits
}

function resolveHitPath(hit: SearchHit): string {
  const alias = hit.alias.trim()
  if (alias.length > 0) {
    return `/${alias}`
  }
  return `/id/${encodeURIComponent(hit.id)}`
}

function navigateTo(path: string) {
  const win = window as SiteSearchWindow
  if (typeof win.__nopSiteNavigate === 'function') {
    win.__nopSiteNavigate(path)
    return
  }
  window.location.assign(path)
}

function getFocusableElements(root: HTMLElement): HTMLElement[] {
  const candidates = Array.from(
    root.querySelectorAll<HTMLElement>(
      'button:not([disabled]),[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'
    )
  )
  return candidates.filter((element) => element.getAttribute('aria-hidden') !== 'true')
}

export function initSearchOverlay(
  root: ParentNode = document
): SiteSearchOverlayController | null {
  const triggerButtons = Array.from(root.querySelectorAll<HTMLButtonElement>(SELECTORS.button))
  const overlay = root.querySelector<HTMLElement>(SELECTORS.overlay)
  const backdrop = root.querySelector<HTMLElement>(SELECTORS.backdrop)
  const panel = root.querySelector<HTMLElement>(SELECTORS.panel)
  const input = root.querySelector<HTMLInputElement>(SELECTORS.input)
  const closeButton = root.querySelector<HTMLButtonElement>(SELECTORS.close)
  const status = root.querySelector<HTMLElement>(SELECTORS.status)
  const results = root.querySelector<HTMLElement>(SELECTORS.results)

  if (
    triggerButtons.length === 0 ||
    !overlay ||
    !backdrop ||
    !panel ||
    !input ||
    !closeButton ||
    !status ||
    !results
  ) {
    return null
  }

  const cleanup: Array<() => void> = []
  let isOpen = false
  let pendingTimer: number | null = null
  let hideTimer: number | null = null
  let inFlight: AbortController | null = null
  let requestSerial = 0
  let activeIndex = -1
  let currentHits: SearchHit[] = []
  let keyboardNavigationActive = false
  let previousBodyOverflow: string | null = null
  let previousFocus: HTMLElement | null = null

  const setKeyboardNavigationActive = (active: boolean) => {
    if (keyboardNavigationActive === active) {
      return
    }
    keyboardNavigationActive = active
    overlay.classList.toggle('is-keyboard-nav', active)
  }

  const clearPendingSearch = () => {
    if (pendingTimer !== null) {
      window.clearTimeout(pendingTimer)
      pendingTimer = null
    }
    if (inFlight) {
      inFlight.abort()
      inFlight = null
    }
    requestSerial += 1
  }

  const renderIdleState = () => {
    status.textContent = ''
    currentHits = []
    activeIndex = -1
    results.textContent = ''
    results.setAttribute('hidden', 'true')
  }

  const renderErrorState = () => {
    status.textContent = "Search didn't work."
    currentHits = []
    activeIndex = -1
    results.textContent = ''
    results.setAttribute('hidden', 'true')
  }

  const renderNoResultsState = () => {
    status.textContent = 'No results'
    currentHits = []
    activeIndex = -1
    results.textContent = ''
    results.setAttribute('hidden', 'true')
  }

  const navigateToHit = (index: number) => {
    if (index < 0 || index >= currentHits.length) {
      return
    }
    const hit = currentHits[index]
    navigateTo(resolveHitPath(hit))
  }

  const renderHits = () => {
    status.textContent = ''
    results.textContent = ''
    if (currentHits.length === 0) {
      results.setAttribute('hidden', 'true')
      return
    }
    results.removeAttribute('hidden')
    const list = document.createElement('ul')
    list.className = 'site-search-results__list'
    list.setAttribute('role', 'listbox')
    list.setAttribute('aria-label', 'Search results')

    currentHits.forEach((hit, index) => {
      const item = document.createElement('li')
      item.className = 'site-search-results__item'

      const button = document.createElement('button')
      button.type = 'button'
      button.className = 'site-search-result'
      button.dataset.siteSearchResultIndex = String(index)
      button.setAttribute('role', 'option')
      button.setAttribute('aria-selected', index === activeIndex ? 'true' : 'false')
      if (index === activeIndex) {
        button.classList.add('is-active')
      }

      const title = document.createElement('span')
      title.className = 'site-search-result__title'
      title.textContent = hit.title
      const path = document.createElement('span')
      path.className = 'site-search-result__path'
      path.textContent = resolveHitPath(hit)
      button.appendChild(title)
      button.appendChild(path)
      item.appendChild(button)
      list.appendChild(item)
    })

    results.appendChild(list)
    const active = results.querySelector<HTMLElement>('.site-search-result.is-active')
    if (active && typeof active.scrollIntoView === 'function') {
      active.scrollIntoView({ block: 'nearest' })
    }
  }

  const setActiveIndex = (index: number) => {
    activeIndex = index
    renderHits()
  }

  const runSearch = async (query: string) => {
    const serial = ++requestSerial
    const controller = new AbortController()
    inFlight = controller

    try {
      const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`, {
        method: 'GET',
        credentials: 'same-origin',
        signal: controller.signal
      })
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      const payload = await response.json()
      if (serial !== requestSerial) {
        return
      }
      currentHits = parseHits(payload)
      activeIndex = -1
      if (currentHits.length === 0) {
        renderNoResultsState()
        return
      }
      renderHits()
    } catch (error) {
      if (controller.signal.aborted || serial !== requestSerial) {
        return
      }
      console.error('Search request failed:', error)
      renderErrorState()
    } finally {
      if (inFlight === controller) {
        inFlight = null
      }
    }
  }

  const scheduleSearch = (rawQuery: string) => {
    clearPendingSearch()
    if (rawQuery.length > SEARCH_MAX_QUERY_LEN) {
      const clamped = rawQuery.slice(0, SEARCH_MAX_QUERY_LEN)
      if (input.value !== clamped) {
        input.value = clamped
      }
      rawQuery = clamped
    }
    const query = normalizeQuery(rawQuery)
    if (query.length < SEARCH_MIN_QUERY_LEN) {
      renderIdleState()
      return
    }
    pendingTimer = window.setTimeout(() => {
      pendingTimer = null
      void runSearch(query)
    }, SEARCH_DEBOUNCE_MS)
  }

  const openOverlay = (initialQuery: string) => {
    if (!isOpen) {
      isOpen = true
      previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
      if (previousBodyOverflow === null) {
        previousBodyOverflow = document.body.style.overflow
      }
      document.body.style.overflow = 'hidden'
      overlay.hidden = false
      if (hideTimer !== null) {
        window.clearTimeout(hideTimer)
        hideTimer = null
      }
      window.requestAnimationFrame(() => overlay.classList.add('is-open'))
    }
    input.value = initialQuery
    setKeyboardNavigationActive(false)
    activeIndex = -1
    scheduleSearch(initialQuery)
    input.focus()
    const position = input.value.length
    input.setSelectionRange(position, position)
  }

  const closeOverlay = () => {
    if (!isOpen) {
      return
    }
    isOpen = false
    clearPendingSearch()
    input.value = ''
    setKeyboardNavigationActive(false)
    renderIdleState()
    overlay.classList.remove('is-open')
    hideTimer = window.setTimeout(() => {
      overlay.hidden = true
      hideTimer = null
    }, SEARCH_OVERLAY_HIDE_MS)
    if (previousBodyOverflow !== null) {
      document.body.style.overflow = previousBodyOverflow
      previousBodyOverflow = null
    }
    previousFocus?.focus()
    previousFocus = null
  }

  const onInput = () => {
    setKeyboardNavigationActive(false)
    activeIndex = -1
    scheduleSearch(input.value)
  }

  const onResultsClick = (event: Event) => {
    const target = event.target instanceof HTMLElement ? event.target : null
    const button = target?.closest<HTMLButtonElement>('[data-site-search-result-index]')
    if (!button) {
      return
    }
    const index = Number(button.dataset.siteSearchResultIndex)
    if (Number.isNaN(index)) {
      return
    }
    navigateToHit(index)
  }

  const onResultsMouseMove = (event: MouseEvent) => {
    if (!isOpen || currentHits.length === 0) {
      return
    }
    const target = event.target instanceof HTMLElement ? event.target : null
    const button = target?.closest<HTMLButtonElement>('[data-site-search-result-index]')
    if (!button) {
      return
    }
    const index = Number(button.dataset.siteSearchResultIndex)
    if (Number.isNaN(index) || index < 0 || index >= currentHits.length) {
      return
    }
    setKeyboardNavigationActive(false)
    if (index !== activeIndex) {
      setActiveIndex(index)
    }
  }

  const trapTabKey = (event: KeyboardEvent) => {
    if (event.key !== 'Tab' || !isOpen) {
      return
    }
    const focusable = getFocusableElements(panel)
    if (focusable.length === 0) {
      event.preventDefault()
      input.focus()
      return
    }
    const current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const currentIndex = current ? focusable.indexOf(current) : -1
    if (event.shiftKey) {
      if (currentIndex <= 0) {
        event.preventDefault()
        focusable[focusable.length - 1].focus()
      }
      return
    }
    if (currentIndex === -1 || currentIndex === focusable.length - 1) {
      event.preventDefault()
      focusable[0].focus()
    }
  }

  const onDocumentKeydown = (event: KeyboardEvent) => {
    if (!isOpen) {
      if (isGlobalSlashShortcut(event)) {
        event.preventDefault()
        openOverlay('')
        return
      }

      if (event.defaultPrevented) {
        return
      }

      if (isSlashShortcut(event)) {
        if (!isEditableTarget(event.target) || isMediaTarget(event.target)) {
          event.preventDefault()
          openOverlay('')
        }
        return
      }

      if (!isPrintableCharacterKey(event) || isEditableTarget(event.target)) {
        return
      }
      event.preventDefault()
      openOverlay(event.key)
      return
    }

    trapTabKey(event)
    if (event.defaultPrevented) {
      return
    }

    if (event.key === 'Escape') {
      event.preventDefault()
      closeOverlay()
      return
    }

    if (event.key === 'ArrowDown') {
      if (currentHits.length === 0) {
        return
      }
      event.preventDefault()
      setKeyboardNavigationActive(true)
      const next = activeIndex < 0 ? 0 : (activeIndex + 1) % currentHits.length
      setActiveIndex(next)
      return
    }

    if (event.key === 'ArrowUp') {
      if (currentHits.length === 0) {
        return
      }
      event.preventDefault()
      setKeyboardNavigationActive(true)
      const next =
        activeIndex < 0
          ? currentHits.length - 1
          : (activeIndex - 1 + currentHits.length) % currentHits.length
      setActiveIndex(next)
      return
    }

    if (event.key === 'Enter') {
      if (activeIndex < 0 || activeIndex >= currentHits.length) {
        return
      }
      event.preventDefault()
      navigateToHit(activeIndex)
      return
    }

    if (!isPrintableCharacterKey(event) || isEditableTarget(event.target)) {
      return
    }
    event.preventDefault()
    input.focus()
    input.value = `${input.value}${event.key}`
    activeIndex = -1
    scheduleSearch(input.value)
  }

  const onOverlayClick = (event: Event) => {
    const target = event.target
    if (target === overlay || target === backdrop) {
      closeOverlay()
    }
  }

  const onButtonClick = (event: Event) => {
    event.preventDefault()
    if (isOpen) {
      closeOverlay()
      return
    }
    openOverlay('')
  }

  const onCloseClick = (event: Event) => {
    event.preventDefault()
    closeOverlay()
  }

  triggerButtons.forEach((button) => button.addEventListener('click', onButtonClick))
  closeButton.addEventListener('click', onCloseClick)
  overlay.addEventListener('click', onOverlayClick)
  input.addEventListener('input', onInput)
  results.addEventListener('click', onResultsClick)
  results.addEventListener('mousemove', onResultsMouseMove)
  document.addEventListener('keydown', onDocumentKeydown)

  triggerButtons.forEach((button) =>
    cleanup.push(() => button.removeEventListener('click', onButtonClick))
  )
  cleanup.push(() => closeButton.removeEventListener('click', onCloseClick))
  cleanup.push(() => overlay.removeEventListener('click', onOverlayClick))
  cleanup.push(() => input.removeEventListener('input', onInput))
  cleanup.push(() => results.removeEventListener('click', onResultsClick))
  cleanup.push(() => results.removeEventListener('mousemove', onResultsMouseMove))
  cleanup.push(() => document.removeEventListener('keydown', onDocumentKeydown))

  renderIdleState()

  return {
    destroy: () => {
      clearPendingSearch()
      if (hideTimer !== null) {
        window.clearTimeout(hideTimer)
      }
      if (previousBodyOverflow !== null) {
        document.body.style.overflow = previousBodyOverflow
        previousBodyOverflow = null
      }
      cleanup.forEach((fn) => fn())
    }
  }
}
