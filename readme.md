# SecretHunter 🎯

SecretHunter is a Static Application Security Testing (SAST) tool written in Python. It is engineered to discover hardcoded credentials, API keys, asymmetric private keys, and sensitive developer annotations hidden within local filesystems or remote Git commit histories.

SecretHunter utilizes an abstract mathematical validation layer alongside strict regular expression signatures to isolate true cryptographic tokens from benign code blocks.

---

## 🚀 Key Features

* **Multi-Threaded Performance:** Powered by a concurrent `ThreadPoolExecutor` architecture to crawl local directory trees and analyze git commit history layers simultaneously.
* **Abstract Mathematical Filtering:** Evaluates string geometry using Shannon Entropy coupled with a unique character density filter and a markup symbol density check to seamlessly filter out safe code structures.
* **Deep Git History Traversal:** Clones remote targets into volatile system memory and walks backward through historical `git diff` branches to uncover keys that developers inadvertently committed and later deleted.
* **Reporting:** Generates outputs in standard text format, structured JSON arrays, or **SARIF v2.1.0** (Static Analysis Results Interchange Format) for native integration into CI/CD pipelines and GitHub Advanced Security code-scanning dashboards.
* **Extensive Global Signatures:** Built-in pattern recognition for cloud service providers (AWS, Azure, GCP, Heroku), communications APIs (Slack, Twilio, Telegram, Discord, SendGrid), payment gateways (Stripe, PayPal, Square), source control (GitHub, GitLab, BitBucket), as well as JWTs, database strings, and raw SSH private keys.
* **Git Pre-Commit Hook**: A hook can be installed on your git repository to prevent data leaks. Supports inline explicit code exemptions natively via the `secret-hunter:ignore` tag.

---

## 📂 Project Structure

```text
secret-hunter/
│
├── hunter.py          # Concurrency orchestration, CLI parsing, hook generation, & reporting
├── rules.py           # Comprehensive signature databases, entropy engines, & structural filters
├── requirements.txt   # Exact third-party project dependencies
└── README.md          # Comprehensive technical documentation
```

## 🛠️ Installation
Clone the repository and install the verified dependencies:

```bash
git clone [https://github.com/Neyrian/secrets-hunter.git](https://github.com/Neyrian/secrets-hunter.git)
cd secret-hunter
pip install -r requirements.txt
```

## 💻 Usage & CLI Reference
You can scan single files, entire local directories, or fully remote repository targets.

### CLI Option Tree
- ```-f```, ```--file``` : Path to a single local target file to scan.
- ```-d```, ```--dir``` : Path to a local project directory to scan recursively.
- ```-g```, ```--git``` : URL of a remote Git repository to deep-scan down to the initial commit.
- ```-t```, ```--threads``` : Total worker thread allocation pool size (Default: 8).
- ```--scan-all```: Tells the scanner to scan all files, including binaries and medias.
- ```--install-hook``` : Automatically binds SecretHunter into your active repository as a native Git hook.
- ```--format``` : Selection array for logging style (text, json, sarif).
- ```-o```, ```--output``` : Destination file target path to write output structures (Required if format is JSON/SARIF).

## 🛡️ Managing False Positives Natively
If SecretHunter encounters a high-entropy mock key, public configuration token, or staging credential that you purposefully intend to keep in your repository, you can configure an inline bypass.

Append the ```# secret-hunter:ignore``` comment tag directly to the evaluated line. The scanning orchestrator will intercept this string match and instantly clear the line from your reporting logs:
```python
# SecretHunter will skip this line automatically during evaluation:
test_environment_key = "d9X!mK92@zLp#qR4"  # secret-hunter:ignore
```