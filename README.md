# kharon

Vaultwarden fill broker: lets AI agents fill credentials without ever seeing them.

Design: [`SPEC.md`](SPEC.md). Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md).

Deploying:

- [`docs/managed-deploy-runbook.md`](docs/managed-deploy-runbook.md): the ordered steps for one managed customer deploy, end to end.
- [`docs/deployment.md`](docs/deployment.md): the deployment guide, the reference each runbook step points into.
- [`docs/broker-lifecycle.md`](docs/broker-lifecycle.md): host install of kharond, backup and restore of `/data`, upgrades, and the secrets inventory.
- [`docs/vault-onboarding.md`](docs/vault-onboarding.md): the customer's Bitwarden organization, collection, dedicated account, and API key.
- [`docs/agent-runtime-setup.md`](docs/agent-runtime-setup.md): the agent side on a hosted or root runtime, and handing over credentials.
- [`deploy/compose/README.md`](deploy/compose/README.md): running kharond with Docker Compose.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
