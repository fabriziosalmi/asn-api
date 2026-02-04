import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'ASN Risk Platform',
  description: 'Autonomous System Risk Intelligence Documentation',
  base: '/asn-api/',
  ignoreDeadLinks: true,

  head: [
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
      { icon: 'github', link: 'https://github.com/your-org/asn-risk-platform' }
    ],

    footer: {
      message: 'ASN Risk Intelligence Platform',
      copyright: 'Copyright 2026'
    },

    search: {
      provider: 'local'
    }
  }
})
