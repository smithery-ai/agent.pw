'use client'

import { useState } from 'react'
import { Copy, Check } from 'lucide-react'

export function CopyBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }

  return (
    <div className="w-fit max-w-full grid gap-1 justify-items-start">
      <button
        type="button"
        onClick={handleCopy}
        className="w-fit max-w-full bg-[#2a2520] text-[#e8e2d0] border border-[rgba(50,44,36,0.2)] rounded-lg px-4 py-3 text-[0.82rem] leading-relaxed font-mono inline-flex items-center gap-3 cursor-pointer transition-all hover:border-primary/30 hover:shadow-md hover:-translate-y-px active:scale-[0.995]"
      >
        <span>{text}</span>
        <span className="text-[#8a8578] shrink-0 transition-opacity">
          {copied ? (
            <Check className="w-4 h-4 text-success" />
          ) : (
            <Copy className="w-4 h-4 opacity-50 hover:opacity-85" />
          )}
        </span>
      </button>
      {copied && (
        <span className="ml-0.5 text-[0.66rem] font-semibold tracking-[0.04em] uppercase text-success">
          Copied — paste to your agent
        </span>
      )}
    </div>
  )
}
