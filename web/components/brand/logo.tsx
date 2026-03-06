export function WardenLogo({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 188 211"
      fill="currentColor"
      aria-hidden="true"
    >
      <defs>
        <clipPath id="shield">
          <path d="M12 0H176Q188 0 188 12V115Q188 185 94 211Q0 185 0 115V12Q0 0 12 0Z" />
        </clipPath>
      </defs>
      <g clipPath="url(#shield)">
        <rect x="-10" y="-10" width="64" height="68" rx="10" />
        <rect x="68" y="-10" width="52" height="68" rx="10" />
        <rect x="134" y="-10" width="64" height="68" rx="10" />
        <rect x="-10" y="72" width="64" height="66" rx="10" />
        <rect x="68" y="72" width="52" height="66" rx="10" />
        <rect x="134" y="72" width="64" height="66" rx="10" />
        <rect x="-10" y="152" width="64" height="69" rx="10" />
        <rect x="68" y="152" width="52" height="69" rx="10" />
        <rect x="134" y="152" width="64" height="69" rx="10" />
      </g>
    </svg>
  )
}
