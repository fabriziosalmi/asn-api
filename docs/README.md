# VitePress Documentation Deployment

This directory contains the VitePress documentation for the ASN Risk Intelligence Platform.

## GitHub Pages Setup

The documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch.

### Prerequisites

To enable GitHub Pages deployment, the repository administrator needs to:

1. Go to repository **Settings** → **Pages**
2. Under **Source**, select "GitHub Actions"
3. Save the settings

The workflow will automatically run on the next push to the `main` branch.

### Manual Deployment

You can also manually trigger the deployment:

1. Go to **Actions** tab in the repository
2. Select "Deploy VitePress Docs to GitHub Pages" workflow
3. Click "Run workflow" → "Run workflow"

## Local Development

To run the documentation locally:

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Documentation Structure

- `api/` - API reference documentation
- `architecture/` - System architecture and design
- `guide/` - User guides and tutorials
- `.vitepress/` - VitePress configuration and theme

## Accessing the Deployed Documentation

Once deployed, the documentation will be available at:
https://fabriziosalmi.github.io/asn-api/

## Troubleshooting

### 404 Errors on GitHub Pages

If you see 404 errors, verify:
1. The `base` path in `.vitepress/config.ts` matches the repository name
2. GitHub Pages is enabled in repository settings
3. The workflow has the correct permissions (pages: write)

### Build Failures

Check the GitHub Actions logs for detailed error messages:
1. Go to **Actions** tab
2. Click on the failed workflow run
3. Review the build logs for errors
