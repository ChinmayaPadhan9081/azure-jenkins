# Cavisson Security Pipeline — Jenkins Conversion

This converts the Azure DevOps extension task `CavSecurityPipelineCP100@1`
(source: `cav-security-pipeline/index.js` + `task.json` + the three shell
scripts) into a declarative Jenkins pipeline with equivalent behavior.

## Files

```
Jenkinsfile                          # the pipeline itself
scripts/cav_scanner.sh               # unchanged from the extension source
scripts/trivy-standalone-wrapper.sh  # unchanged from the extension source
scripts/zap-standalone-wrapper.sh    # unchanged from the extension source
scripts/check-docker.sh              # NEW — Jenkins-side docker preflight
scripts/get-cav-tokens.sh            # NEW — replaces lib/codeAnalyzerRunner.js's getToken() call
scripts/call-security-scan-api.sh    # NEW — replaces lib/securityScanApi.js's callSecurityScanApi()
```

Put the `scripts/` folder at the root of the repository the Jenkinsfile
lives in (or adjust `SCRIPTS_DIR` in the `environment {}` block if you keep
them elsewhere, e.g. a shared library).

## One important behavioral decision

The real Azure `index.js` also POSTs standalone Trivy/ZAP results to a
Mongo-backed reporting endpoint (`saveSecurityReportToMongo`,
`.../config/module/<module>/objects`) **even in standalone mode**. Your
spec explicitly states:

> 5. Standalone Trivy/ZAP should not call REST API.
> 6. Kubernetes Trivy/ZAP should call REST API only.

This Jenkinsfile follows your stated spec, not that extra Mongo call. If
you actually still want standalone runs to also push results to that
`/config/module/<module>/objects` endpoint, say so and I'll add it back as
an additional step — it's a straightforward addition to the "Collect
Reports" stage.

---

## Jenkins setup required before first run

### 1. Credentials
Create a **Secret Text** credential in Jenkins (Manage Jenkins → Credentials):

| Field | Value |
|---|---|
| Kind | Secret text |
| ID | `cavisson-api-token` |
| Secret | the API token that used to live in the Azure DevOps Service Connection (`endpoint.parameters.apitoken`) |

This single credential replaces the whole Azure Service Connection object.
It's used for:
- the static-scan token exchange (`get-cav-tokens.sh`)
- the Kubernetes-mode REST orchestration call (`call-security-scan-api.sh`)

### 2. Agent requirements
The agent (or agent label you pin the job to) needs: `bash`, `docker` (daemon
reachable by the Jenkins user), `curl`, `jq`, `tar`. `python3` is only needed
if you re-enable the optional Trivy JSON→HTML conversion (see note below).

### 3. Job parameters
Create the job as a **Pipeline** (or Multibranch Pipeline) pointing at this
`Jenkinsfile`. Jenkins will auto-populate the parameters form from the
`parameters {}` block on first run/scan — no manual parameter setup needed.

---

## Azure DevOps → Jenkins concept mapping

| Azure DevOps concept | Where it lived | Jenkins equivalent | Notes |
|---|---|---|---|
| **Service Connection** (`cavScanServiceConnection`, type `connectedService:...`) | `task.json` input, resolved via `tl.getEndpointUrl()` / `tl.getEndpointAuthorization()` | `BASE_URL` string **parameter** + `cavisson-api-token` **Secret Text credential** | Azure bundled "base URL" and "auth token" into one service connection object. Jenkins has no first-class equivalent, so it's split: URL is a plain parameter (not secret), token is a credential (secret, masked in logs). |
| **Task input** (`tl.getInput(...)`) | `task.json` inputs, e.g. `scanType`, `project`, `trivyMode`, `zapTarget` | Pipeline `parameters { choice(...) / string(...) }` | 1:1 rename: `project`→`PROJECT_KEY`, `targetPath`→`TARGET_PATH`, `containerRunMode`→`CONTAINER_RUN_MODE`, `trivyMode`→`TRIVY_MODE`, `trivyTarget`→`TRIVY_TARGET`, `dynamicRunMode`→`DYNAMIC_RUN_MODE`, `zapMode`→`ZAP_MODE`, `zapTarget`→`ZAP_TARGET`. |
| **`visibleRule`** conditional UI fields | `task.json` | `when { expression { ... } }` per stage, plus manual `if` checks in **Validate Inputs** | Azure hides irrelevant fields in the UI; Jenkins always shows all parameters but the pipeline logic ignores/validates the irrelevant ones based on `SCAN_TYPE` / `*_RUN_MODE`. |
| **Pipeline Artifact** (`##vso[artifact.upload]`, `tl.uploadArtifact`) | `publishSingleArchiveAsAzureArtifact()` in `index.js` | `archiveArtifacts` step | Azure uploads a single `.tar.gz`; this pipeline archives the collected report folder directly (`security-reports/**`) so files are browsable individually in the Jenkins UI. Add a `tar -czf` + single-file archive step yourself if you specifically need one archive blob instead. |
| **Azure hosted agent** (Microsoft-hosted `ubuntu-latest`, etc.) | pipeline YAML `pool:` | `agent any` / `agent { label 'docker' }` | Swap `agent any` for `agent { label '<your-docker-capable-label>' }` once you've tagged the right Jenkins agents. Nothing else changes. |
| **Self-hosted agent / Deployment Group** | Azure agent pool | Any Jenkins agent/node matching the label you choose | Same idea — a long-lived machine registered with the controller. Docker + bash + curl + jq must be present, exactly like the Azure self-hosted agent needed them. |
| **`tl.setSecret(value)`** | scattered through `index.js` | `withCredentials([...])` auto-masking + explicit avoidance of `echo`ing token values in scripts | Jenkins masks bound credential values automatically; the derived Sonar tokens fetched at runtime are *not* auto-masked, so `get-cav-tokens.sh` deliberately never prints them and writes them to a file that's deleted immediately after use. |
| **`$(System.DefaultWorkingDirectory)` / `$(Build.BuildNumber)` / `$(Build.SourcesDirectory)`** | Azure predefined variables | `${WORKSPACE}`, `${env.BUILD_NUMBER}`, `${env.JOB_NAME}` | Direct Jenkins environment variable equivalents. |
| **Task execution runtime** (`Node16`, `index.js`) | `task.json` → `execution.Node16.target` | Groovy `Jenkinsfile` + `sh` steps calling the same bash scripts | The Node.js orchestration layer (`index.js`) is replaced by pipeline Groovy logic. The actual scanning logic (the three `.sh` files) is reused unmodified — that was already portable shell. |

---

## Stage-by-stage mapping to your numbered requirements

1. **Validate Inputs** — replicates `validateRequiredInput()` / `validateKubernetesInputs()`, plus runs `check-docker.sh` before any standalone Trivy/ZAP stage (requirement 10).
2. **Static Scan** — replicates `runCodeAnalyzer()`: exchanges the Cavisson API token for Sonar tokens (`get-cav-tokens.sh`, mirrors the old `getToken` REST call), then runs `cav_scanner.sh` unchanged.
3. **Container Scan** — standalone branch runs `trivy-standalone-wrapper.sh` with `--mode/--target/--report-dir` exactly like `runTrivyStandalone()` did; kubernetes branch calls `call-security-scan-api.sh` with the fixed payload `{"scanDast": false, "scanSca": true}` (requirement 3/6).
4. **Dynamic Scan** — standalone branch runs `zap-standalone-wrapper.sh` (HTML/JSON/XML reports, requirement 4) with an explicit `returnStatus` safety net so ignored ZAP warnings never fail the build (requirement 9); kubernetes branch posts `{"scanDast": true, "scanSca": false}` (requirement 4/6).
5. **Collect Reports** — builds the unique folder `security-reports/<JOB_NAME>/<BUILD_NUMBER>/<timestamp>/`, copying Trivy/ZAP raw output into it (requirement 7), and writes a JSON summary (mirrors `security-report-summary.json`). Skipped entirely for static scans, per requirement 8.
6. **Publish Artifacts** — `archiveArtifacts` on the collected folder, only when files exist; also re-attempted in `post { always { ... } }` so a mid-scan failure still preserves whatever reports were produced (mirrors the `catch` block in `index.js`).

## Optional: Trivy JSON → HTML conversion

The original extension shipped `trivy_json_to_html.py` and called it from
`generateTrivyHtmlReport()` (only used for the Mongo-report path we
intentionally dropped per your spec above). If you want an HTML view of
the Trivy JSON in the archived artifacts, add this to the end of the
standalone branch of the **Container Scan** stage:

```groovy
sh "python3 '${SCRIPTS_DIR}/trivy_json_to_html.py' <json-file> <html-file>"
```

(copy `trivy_json_to_html.py` from the original zip into `scripts/` if you
want this.)

## Running it

Trigger a build and fill in the parameter form, e.g. for a standalone
container scan:

- `SCAN_TYPE=container`
- `CONTAINER_RUN_MODE=standalone`
- `TRIVY_MODE=image`
- `TRIVY_TARGET=myrepo/myapp:1.0.0`
- `BASE_URL=https://cavisson.example.com`

Or for a Kubernetes-mode dynamic scan:

- `SCAN_TYPE=dynamic`
- `DYNAMIC_RUN_MODE=kubernetes`
- `BASE_URL=https://cavisson.example.com`

(`ZAP_MODE`/`ZAP_TARGET` are ignored in kubernetes mode, exactly like the
Azure task hid them via `visibleRule`.)
