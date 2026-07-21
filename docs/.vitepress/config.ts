import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'ASN Risk Platform',
  description: 'Autonomous System Risk Intelligence Documentation',
  base: '/asn-api/',
  ignoreDeadLinks: true,

  head: [
    // Everything this site loads is first-party. 'unsafe-inline' is required
    // because VitePress emits an inline appearance script and inline styles.
    // Applied to the built site only: `vitepress dev` serves HMR over a
    // websocket, which a strict connect-src would block as soon as the dev
    // server is not same-origin (--host, or a custom server.hmr.port).
    ...(process.env.NODE_ENV === 'production'
      ? [
          [
            'meta',
            {
              'http-equiv': 'Content-Security-Policy',
              content:
                "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'",
            },
          ] as [string, Record<string, string>],
        ]
      : []),
    ['link', { rel: 'icon', href: '/asn-api/favicon.ico' }]
  ],

  themeConfig: {
    logo: '/logo.svg',

    nav: [
      { text: 'Guide', link: '/guide/' },
      { text: 'API Reference', link: '/api/' },
      { text: 'Architecture', link: '/architecture/' }
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Introduction', link: '/guide/' },
            { text: 'Quick Start', link: '/guide/quickstart' },
            { text: 'Configuration', link: '/guide/configuration' }
          ]
        },
        {
          text: 'Concepts',
          items: [
            { text: 'Scoring Model', link: '/guide/scoring' },
            { text: 'Signals', link: '/guide/signals' }
          ]
        },
        {
          text: 'Integrations',
          items: [
            { text: 'Firewall EDL / Real-Time Stream', link: '/guide/integrations' }
          ]
        }
      ],
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Overview', link: '/api/' },
            { text: 'Authentication', link: '/api/authentication' },
            { text: 'Endpoints', link: '/api/endpoints' },
            { text: 'Response Schema', link: '/api/schema' },
            { text: 'Field Reference', link: '/api/fields' },
            { text: 'Examples', link: '/api/examples' }
          ]
        }
      ],
      '/architecture/': [
        {
          text: 'Architecture',
          items: [
            { text: 'Overview', link: '/architecture/' },
            { text: 'Data Flow', link: '/architecture/data-flow' },
            { text: 'Database Schema', link: '/architecture/database' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/asn-api' }
    ],

    footer: {
      message: 
        'ASN Risk Intelligence Platform · <a href="https://fabriziosalmi.github.io/privacy">Privacy &amp; legal</a>',
      copyright: 'Copyright 2026'
    },

    search: {
      provider: 'local'
    }
  }
})
