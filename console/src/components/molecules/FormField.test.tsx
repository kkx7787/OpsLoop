import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Input } from '../atoms/Input'
import { FormField } from './FormField'

describe('FormField', () => {
  it('라벨 · 도움말을 입력과 잇는다', () => {
    render(
      <FormField label="아이디" hint="관리자가 만든 계정">
        {(f) => <Input {...f} />}
      </FormField>,
    )
    const input = screen.getByLabelText('아이디')
    expect(input).toHaveAccessibleDescription('관리자가 만든 계정')
    expect(input).not.toHaveAttribute('aria-invalid')
  })

  it('오류가 있으면 aria-invalid 와 오류 설명을 붙인다', () => {
    render(
      <FormField label="판정 근거" required error="근거를 적어 주세요">
        {(f) => <Input {...f} />}
      </FormField>,
    )
    const input = screen.getByRole('textbox', { name: /판정 근거/ })
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toBeRequired()
    expect(input).toHaveAccessibleDescription('근거를 적어 주세요')
  })
})
