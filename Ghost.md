Install and setup: https://ai-productivity.splunkdev.page/handbook/users/get-started/install-and-set-up/#install

Getting-Started: https://splunk.atlassian.net/wiki/spaces/POP/pages/1080074600456/Getting+Started+Claude+Code+with+Ghost

Re-running and repair:
```
./install.sh --verify # end-to-end check of everything --all installs
./install.sh --all --force # reinstall/reconfigure everything 
./install.sh --ghost --force # repair a single component 
./install.sh --check-gitlab # check GitLab SSH access, and set up a key if needed
```

### Prompt Library
[Invocation Patterns](https://ai-productivity.splunkdev.page/handbook/users/reference/prompts/#invocation-patterns "Permanent link")
- Codex skills: `$skill-name`
- Claude plugin skills: `/plugin-name:skill-name`
- MCP-routed prompts: `Use <service> MCP ...`

### Wind-down
That's the whole shape: refresh in the morning, plan before you act, troubleshoot with your agent when something breaks. The rhythm becomes muscle memory in about a week.
### Skills Marketplace
https://ai-productivity.splunkdev.page/handbook/users/reference/skills-marketplace/#use-ghost-first
