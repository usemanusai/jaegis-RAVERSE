# Package Distribution Guide

Guide for package maintainers and developers on distributing RAVERSE MCP Server.

## Table of Contents
1. [NPM Distribution](#npm-distribution)
2. [PyPI Distribution](#pypi-distribution)
3. [Docker Distribution](#docker-distribution)
4. [Version Management](#version-management)
5. [Release Process](#release-process)
6. [Maintenance](#maintenance)

---

## NPM Distribution

### Package Structure

```
@raverse/mcp-server
├── bin/
│   └── raverse-mcp-server.js      # CLI entry point
├── jaegis_raverse_mcp_server/      # Python package
├── tests/                          # Test suite
├── package.json                    # NPM metadata
├── .npmignore                      # Files to exclude
├── pyproject.toml                  # Python config
├── requirements.txt                # Python dependencies
├── README.md                       # User guide
├── INSTALLATION.md                 # Installation guide
├── MCP_CLIENT_SETUP.md            # Client setup
└── LICENSE                         # MIT License
```

### Publishing to NPM

#### 1. Prepare Package
```bash
# Update version in package.json
npm version patch  # or minor, major

# Update version in pyproject.toml
# Update CHANGELOG.md

# Commit changes
git add .
git commit -m "Release v1.0.1"
git tag v1.0.1
```

#### 2. Build Package
```bash
# Clean previous builds
npm run clean

# Build Python package
npm run build

# Verify package contents
npm pack --dry-run
```

#### 3. Login to NPM
```bash
# Login to npm registry
npm login

# Enter credentials:
# Username: usemanusai
# Password: [your npm password]
# Email: use.manus.ai@gmail.com
```

#### 4. Publish Package
```bash
# Publish to npm (scoped package)
npm publish --access public

# Verify publication
npm view @raverse/mcp-server

# Test installation
npm install -g @raverse/mcp-server
raverse-mcp-server --version
```

### NPM Package Metadata

**package.json** includes:
- Name: `@raverse/mcp-server`
- Version: Semantic versioning (1.0.0)
- Description: Clear, concise description
- Keywords: Searchable terms
- Repository: GitHub URL
- License: MIT
- Bin: CLI entry point
- Files: Included files list
- Scripts: npm commands

### NPM Registry

- **Registry**: https://registry.npmjs.org/
- **Package URL**: https://www.npmjs.com/package/@raverse/mcp-server
- **Scope**: @raverse (organization scope)

---

## PyPI Distribution

### Package Structure

```
jaegis-raverse-mcp-server
├── jaegis_raverse_mcp_server/      # Python package
├── tests/                          # Test suite
├── pyproject.toml                  # Package metadata
├── requirements.txt                # Dependencies
├── MANIFEST.in                     # Additional files
├── README.md                       # User guide
├── LICENSE                         # MIT License
└── setup.py                        # Setup script (optional)
```

### Publishing to PyPI

#### 1. Prepare Package
```bash
# Update version in pyproject.toml
# Update CHANGELOG.md

# Commit changes
git add .
git commit -m "Release v1.0.1"
git tag v1.0.1
```

#### 2. Build Package
```bash
# Install build tools
pip install build twine

# Build distribution
python -m build

# Verify build
ls -la dist/
# Should contain:
# - jaegis_raverse_mcp_server-1.0.1-py3-none-any.whl
# - jaegis_raverse_mcp_server-1.0.1.tar.gz
```

#### 3. Configure PyPI Credentials
```bash
# Create ~/.pypirc
cat > ~/.pypirc << EOF
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = usemanusai
password = [your pypi token]

[testpypi]
repository = https://test.pypi.org/legacy/
username = usemanusai
password = [your test pypi token]
EOF

# Set permissions
chmod 600 ~/.pypirc
```

#### 4. Test Upload (Optional)
```bash
# Upload to TestPyPI first
python -m twine upload --repository testpypi dist/*

# Test installation
pip install -i https://test.pypi.org/simple/ jaegis-raverse-mcp-server
```

#### 5. Publish to PyPI
```bash
# Upload to PyPI
python -m twine upload dist/*

# Verify publication
pip search jaegis-raverse-mcp-server

# Test installation
pip install jaegis-raverse-mcp-server
raverse-mcp-server --version
```

### PyPI Package Metadata

**pyproject.toml** includes:
- Name: `jaegis-raverse-mcp-server`
- Version: Semantic versioning
- Description: Clear description
- Keywords: Searchable terms
- Classifiers: Package categorization
- URLs: Homepage, docs, repository
- Dependencies: Required packages
- Entry points: CLI commands

### PyPI Registry

- **Registry**: https://pypi.org/
- **Package URL**: https://pypi.org/project/jaegis-raverse-mcp-server/
- **Test Registry**: https://test.pypi.org/

---

## Docker Distribution

### Dockerfile

```dockerfile
FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY pyproject.toml requirements.txt ./
COPY jaegis_raverse_mcp_server/ ./jaegis_raverse_mcp_server/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD raverse-mcp-server --health-check || exit 1

# Run server
CMD ["raverse-mcp-server"]
```

### Building Docker Image

```bash
# Build image
docker build -t raverse/mcp-server:latest .

# Tag for registry
docker tag raverse/mcp-server:latest raverse/mcp-server:1.0.1

# Push to Docker Hub
docker push raverse/mcp-server:latest
docker push raverse/mcp-server:1.0.1
```

### Docker Registry

- **Registry**: Docker Hub (https://hub.docker.com/)
- **Image**: `raverse/mcp-server`
- **Tags**: `latest`, version tags (1.0.1, 1.0, 1)

---

## Version Management

### Semantic Versioning

Format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

### Version Files

Update in all locations:
1. `package.json` - NPM version
2. `pyproject.toml` - Python version
3. `Dockerfile` - Base image versions
4. `CHANGELOG.md` - Release notes
5. Git tags - Version tags

### Version Bumping

```bash
# Patch release (1.0.0 -> 1.0.1)
npm version patch

# Minor release (1.0.0 -> 1.1.0)
npm version minor

# Major release (1.0.0 -> 2.0.0)
npm version major
```

---

## Release Process

### Pre-Release Checklist

- [ ] All tests passing
- [ ] Code reviewed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in all files
- [ ] No breaking changes (or documented)
- [ ] Security audit completed
- [ ] Performance tested

### Release Steps

1. **Create Release Branch**
```bash
git checkout -b release/v1.0.1
```

2. **Update Version**
```bash
npm version patch
```

3. **Update Changelog**
```bash
# Edit CHANGELOG.md with release notes
git add CHANGELOG.md
git commit -m "Update changelog for v1.0.1"
```

4. **Create Pull Request**
```bash
git push origin release/v1.0.1
# Create PR on GitHub
```

5. **Merge to Main**
```bash
# After approval, merge PR
git checkout main
git pull origin main
```

6. **Tag Release**
```bash
git tag -a v1.0.1 -m "Release v1.0.1"
git push origin v1.0.1
```

7. **Publish Packages**
```bash
# Publish to npm
npm publish --access public

# Publish to PyPI
python -m twine upload dist/*

# Push Docker image
docker push raverse/mcp-server:1.0.1
```

8. **Create GitHub Release**
```bash
# On GitHub, create release from tag
# Include release notes and download links
```

---

## Maintenance

### Dependency Updates

```bash
# Check for outdated packages
npm outdated
pip list --outdated

# Update packages
npm update
pip install --upgrade -r requirements.txt

# Test after updates
npm test
pytest tests/
```

### Security Updates

```bash
# Check for vulnerabilities
npm audit
pip-audit

# Fix vulnerabilities
npm audit fix
pip install --upgrade [package]
```

### Monitoring

- Monitor GitHub issues
- Track download statistics
- Monitor package health
- Respond to user feedback

### Support

- **GitHub Issues**: https://github.com/usemanusai/jaegis-RAVERSE/issues
- **Discussions**: https://github.com/usemanusai/jaegis-RAVERSE/discussions
- **Email**: team@raverse.ai

---

## Troubleshooting

### NPM Publishing Issues

```bash
# Check npm login
npm whoami

# Clear npm cache
npm cache clean --force

# Verify package
npm pack --dry-run

# Check registry
npm view @raverse/mcp-server
```

### PyPI Publishing Issues

```bash
# Check credentials
twine --version

# Verify package
twine check dist/*

# Check PyPI
pip search jaegis-raverse-mcp-server
```

### Docker Issues

```bash
# Check image
docker images | grep raverse

# Test image
docker run raverse/mcp-server:latest --version

# Check registry
docker search raverse
```

---

**Last Updated**: October 27, 2025
**Version**: 1.0.0

