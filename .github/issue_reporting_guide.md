### **Issue Reporting Guide for Dexfile**

This guide will help you report issues with the **Dexfile BuildKit frontend**.

---

### **Security Issues**

Do NOT report security issues publicly. See the project's security policy at **`https://github.com/dexfile/dexfile/security/policy`** (assuming this is the repository URL).

---

### **Search for an Existing Issue**

Before creating a new issue, check to see if a similar one has already been reported. Search the repository with relevant keywords. If you find a related issue, you can provide new information or signal your interest with a reaction. If you're unsure whether your problem is the same, open a new issue and link to the previous one so a maintainer can decide.

---

### **Reproducible Test Case**

The best way to help us is by providing a simple, reproducible test case. A test case that runs in a container is ideal, as it's easy for maintainers to replicate without having the same local setup as you. 

Try to simplify your build case until you find the minimal set of instructions that reproduce the problem. Even if your issue is from a complex production build, you can often narrow it down to a few key lines of a Dexfile.

If you've provided a reproducible test case, a maintainer will verify it and mark the issue as **"confirmed,"** which means it's ready to be worked on. If the issue only appears intermittently, a test case that reproduces the problem 10-20% of the time is still very helpful.

---

### **Describe Your Environment**

Provide enough detail about your environment so we can replicate your issue.

* **Dexfile Frontend Version:** The version of the Dexfile binary you're using.
* **BuildKit Version:** The version of the BuildKit daemon you're connected to.
* **Client Tool:** The client you're using to run the build (e.g., `docker buildx`, `buildctl`).
* **Operating System:** The OS you're running on (e.g., Ubuntu, macOS, Windows).
* **Build Environment:** Any specific configurations, such as a custom BuildKit instance, a specific container runtime, or a unique filesystem.

If you're using an older version of the Dexfile frontend, try to reproduce the problem with the latest version before reporting.

---

### **Reporting Panics or Errors**

When your build unexpectedly fails with an error or a panic, include the **full error message** and **stack trace** in your report. This information is crucial for us to identify the code path that caused the issue.

If you're using `docker buildx`, you can often get more detailed logs by running your command with the `--debug` flag.

---

### **Gathering More Debugging Data**

If a simple error message isn't enough, check the logs of your BuildKit daemon for any extra information and include them in your report. You can enable debug logs on the daemon for more verbose output.

---

### **Regressions**

If you notice a bug that was not present in a previous version, this is a **regression**. Label your issue clearly with **"[Regression]"** in the title. If possible, use `git bisect` on the Dexfile repository to find the exact commit that introduced the issue. This saves us a lot of time and helps us prioritize the fix.

---

### **Follow the Progress of Your Issue**

You can help by checking if your issue is properly labeled by a maintainer. If a bug report is confirmed, it will be marked as **"bug"** and **"confirmed."** If it needs more information from you, it will be marked **"needs-more-info."**

You can also ask to be assigned the issue if you'd like to try fixing it yourself.

---

### **Additional Reading**

* Code of Conduct: **`https://github.com/dexfile/dexfile/blob/master/.github/CODE_OF_CONDUCT.md`**
* Contributing Guide: **`https://github.com/dexfile/dexfile/blob/master/.github/CONTRIBUTING.md`**