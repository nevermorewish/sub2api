import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiClient } from '../client'
import { runAccountAutoMonitorNow } from '../admin/scheduledTests'

afterEach(() => vi.restoreAllMocks())

describe('scheduled tests API', () => {
  it('runs the global account monitor immediately', async () => {
    const response = {
      total: 3,
      succeeded: 2,
      failed: 1,
      settings: {
        enabled: true,
        interval_minutes: 30,
        running: false
      }
    }
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: response })

    await expect(runAccountAutoMonitorNow()).resolves.toEqual(response)
    expect(post).toHaveBeenCalledWith(
      '/admin/accounts/auto-monitor/run',
      undefined,
      { timeout: 300_000 }
    )
  })
})
