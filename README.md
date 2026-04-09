# Detection-as-Code Pipeline

Detection engineering pipeline for AWS. Rules are YAML, tested with pytest,
validated in CI, and deployed to Elastic Security.

I built this to practice development, deployment, and usage of a DaC pipeline.
Not just rules sitting in a repo, but the full loop from authoring to
deployment to alerts firing against data.

## Detection format

Rules use a Sigma YAML schema.

## License

MIT