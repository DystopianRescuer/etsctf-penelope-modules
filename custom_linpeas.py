"""
Custom linpeas for ETSCTF-based CTFs wrapper penelope module
by DystopianRescuer

Modified linpeas version by mrtaichi
"""

LINPEAS_URL = (
    "https://github.com/IsaacNietoG/PEASS-ng/releases/latest/download/linpeas_ctf.sh"
)


class linpeas(Module):
    enabled = True
    category = "ETSCTF"
    on_session_start = False
    on_session_end = False

    def run(session, args):
        """
        Custom linpeas (IA included)
        """

        # AI Analysis functions
        def preprocess_linpeas(output_text):
            # Remove ANSI
            clean_text = re.sub(
                r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", output_text
            )
            # Tag sensitive (simulando resaltar, si codes ya removidos, usa regex post-limpieza)
            clean_text = re.sub(
                r"(passw(?:ord|d)|credential|key)",
                r"[sensitive]\1[/sensitive]",
                clean_text,
                flags=re.IGNORECASE,
            )
            # Skipping Hacktricks URLS
            clean_text = re.sub(r"https?://[^\s]+", "", clean_text)
            # Skip arte ASCII: Find first section
            start = clean_text.find("╔══════════╣")
            if start != -1:
                clean_text = clean_text[start:]
            # Split sections
            sections_raw = re.split(r"╔══════════╣", clean_text)[1:]
            processed = []
            for sec in sections_raw:
                lines = sec.strip().split("\n")
                if lines:
                    title = lines[0].strip()  # Mejor: directo strip
                    content = "\n".join(lines[1:]).strip()
                    # Remove ASCII box characters
                    content = re.sub(r"[\u2500-\u257F]", "", content)
                    content = content.replace("└─", "- ")
                    # Normalize spaces and empty lines
                    content = re.sub(r"\n\s*\n+", "\n", content).strip()
                    # Final processing: Getting the data type
                    newItem = peass_ng.processSection(title, content)
                    # Appending
                    if newItem["is_empty"]:
                        continue
                    processed.append(
                        {
                            "title": title,
                            "content_type": newItem["content_type"],
                            "content": newItem["structured_content"],
                            "is_empty": newItem["is_empty"],
                        }
                    )

            return json.dumps({"sections": processed}, indent=4)

        def processSection(title, content):
            content_type = "text"
            structured_content = content
            is_empty = not bool(content.strip())

            # Estructurar como lista
            if (
                "files" in title.lower()
                or "processes" in title.lower()
                or "searching" in title.lower()
            ):
                content_type = "list"
                items = []
                current_process = None
                current_files = []

                for line in content.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("Process ") and " - " in line:
                        if current_process and current_files:
                            items.append(
                                {"process": current_process, "files": current_files}
                            )
                        current_process = line
                        current_files = []
                    elif line.startswith("- "):
                        current_files.append(line[2:].strip())
                    else:
                        items.append(line)
                if current_process and current_files:
                    items.append({"process": current_process, "files": current_files})
                structured_content = items if items else []
                is_empty = len(structured_content) == 0

            # Estructurar como key-value
            elif "environment" in title.lower() or "operative system" in title.lower():
                content_type = "key_value"
                key_value = {}
                for line in content.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    if "=" in line and not line.startswith("- "):
                        key, value = line.split("=", 1)
                        key_value[key.strip()] = value.strip()
                    elif ":" in line and "operative system" in title.lower():
                        key, value = line.split(":", 1)
                        key_value[key.strip()] = value.strip()
                structured_content = key_value
                is_empty = len(key_value) == 0

            return {
                "content_type": content_type,
                "structured_content": structured_content,
                "is_empty": is_empty,
            }

        prompt = """You are an expert cybersecurity analyst specializing in Capture The Flag (CTF) challenges, particularly for the Hackmex CTF Finals, with adaptability for other CTFs. Your task is to analyze a preprocessed JSON output from LinPEAS and generate a concise, detailed report focused on identifying potential privilege escalation vectors. The JSON contains sections with the following structure:
      - **title**: The section title (e.g., "Sudoers", "Cron jobs").
      - **content_type**: The type of content ("list", "key_value", or "text").
      - **content**: The structured content (array for lists, dictionary for key-value, string for text).
      - **is_empty**: Boolean indicating if the section is empty or irrelevant (e.g., "Not Found").
      - Terms like "password", "credential", or "key" are tagged as [sensitive]...[/sensitive].

      **Your report must:**

      1. **Critical Findings**: List specific findings highly likely to be exploitable, prioritizing Hackmex vectors. Your analysis must go beyond keyword matching and focus on contextual deduction.
         - **Mandatory Section Check**: Explicitly analyze the section titled "Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d'" first, as it is the most likely privilege escalation vector (99% of CTF challenges). If this section exists and is not empty, highlight any binaries or commands runnable with `(ALL : ALL) NO[sensitive]PASSWD[/sensitive]` and treat them as the top priority. For each such binary:
           - Research its functionality (e.g., is it a script, daemon, or executable?).
           - Suggest specific exploitation methods (e.g., command injection, environment variable manipulation, or known vulnerabilities).
           - Cross-reference with the system’s OS (from "Operative system") to ensure compatibility.
         - Correlate software versions (e.g., from "Sudo version", "Kernel version") with known public vulnerabilities (CVEs), ensuring relevance to the system (e.g., Debian, kernel version).
         - Identify SUID/SGID binaries, especially non-standard ones outside /usr/bin, and validate their exploitability (e.g., discard /usr/bin/passwd on Linux/Debian unless specific conditions apply).
         - Look for non-standard configurations of services (e.g., unusual sudoers entries, writable cron jobs).
         - Focus on non-standard or third-party software (e.g., in /opt, /usr/local, or indicated by "RAILS_ENV: development" or unusual PATH entries), as these are common CTF vectors.
         - Analyze custom services (e.g., "SUPERVISOR_PROCESS_NAME") for misconfigurations or vulnerabilities.
      2. **Potential Risks**: Highlight findings requiring further investigation, focusing on context.
         - Unusual environment variables or service configurations that expand the attack surface.
         - Information from "Container & breakout enumeration" and mount-related sections for potential container escape vectors.
         - Binaries or services in non-standard locations (e.g., /opt, /usr/local).
      3. **Recommendations**: Provide actionable steps to exploit findings.
         - Formulate specific commands or attack methods based on correlated findings.
         - For non-standard software, suggest searching for known exploits or misconfigurations tied to its version or name.
         - For sudo-runnable binaries, provide tailored exploitation commands or scripts.
      4. **Additional Notes**: Include observations that may not be direct vectors but are useful.
         - Summarize system protections (ASLR, Seccomp, etc.) and note disabled protections.
         - Specify the current user’s privileges and group memberships.

      **Validation Rules for Findings**:
      - Ignore low-probability vulnerabilities:
        - SUID binaries not running vulnerable versions (e.g., /usr/bin/passwd only if on OSX/Solaris/SPARC; discard on Linux/Debian).
        - Container escapes unless clear misconfigurations (e.g., writable mounts, dangerous capabilities).
        - Kernel vulnerabilities not matching the system’s kernel version or OS.
      - Cross-reference system details (e.g., "Operative system" section) with research to ensure relevance.
      - **Section Validation**: Before finalizing the report, explicitly verify that the "Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d'" section has been processed. If it exists and is not empty, ensure its contents are fully analyzed and prominently featured in the "Critical Findings" section. If absent, note this explicitly in the "Additional Notes" section.

      **Error Prevention**:
      - **Section Enumeration**: Process every JSON section systematically, logging each section title to ensure none are skipped. If a section is missed (e.g., due to parsing errors), include a warning in the report: "Warning: Potential parsing error; verify section [title] manually."
      - **Priority Highlighting**: Use a checklist to confirm analysis of high-priority sections (e.g., sudoers, environment variables, running processes) before generating the report.
      - **Verbose Logging for Debugging**: If a critical section like sudoers is empty or absent, include a note in the report explaining why (e.g., "Section not found in JSON" or "Section empty, manual sudo -l recommended").

      **Output Format**:
      ```markdown
      # LinPEAS Analysis Report
      ## Critical Findings
      - [Finding 1]: [e.g., "User can run /usr/bin/floppyd as (ALL : ALL) NOPASSWD, potentially exploitable via command injection."]
      - [Finding 2]: [e.g., "Sudo version 1.9.13p3 vulnerable to CVE-2021-3156."]
      ---
      ## Potential Risks
      - [Risk 1]: [e.g., "Supervisord process 'camaleon' may have misconfigured credentials."]
      ---
      ## Recommendations
      - [Action 1]: [e.g., "Test /usr/bin/floppyd with sudo: `sudo /usr/bin/floppyd /tmp/malicious.sh`."]
      - [Action 2]: [e.g., "Exploit CVE-2021-3156: `sudoedit -s '\' $(perl -e 'print "A" x 65536')`."]
      ---
      ## Additional Notes
      - [Note 1]: [e.g., "ASLR disabled, increasing exploit reliability."]
      - [Note 2]: [e.g., "Sudoers section processed; no other NOPASSWD binaries found."]
      ```

      **Additional Instructions**:
      - Ensure the report is concise yet comprehensive, avoiding redundant details.
      - If a section like "Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d'" is present, it must be the first analyzed and reported under "Critical Findings."
      - If unsure about a binary’s exploitability (e.g., /usr/bin/floppyd), suggest manual enumeration (e.g., `strings`, `file`, `--help`) and research for known exploits.
      - Current date: [Insert current date]. Cross-reference findings with the system’s timestamp (e.g., from "Date & uptime") to ensure temporal relevance."""

        parser = ArgumentParser(
            prog="peass_ng", description="peass-ng module", add_help=False
        )
        parser.add_argument(
            "-a",
            "--ai",
            help="Analyze linpeas results with chatGPT",
            action="store_true",
        )
        try:
            arguments = parser.parse_args(shlex.split(args))
        except SystemExit:
            return

        if arguments.ai:
            try:
                from openai import OpenAI
            except Exception as e:
                logger.error(e)
                return False

            # check if API key defined in peneloperc
            try:
                if openia_apikey != None:
                    api_key = openia_apikey
            except NameError:
                logger.error(
                    "API Key no definida, definela como openai_apikey en peneloperc"
                )

        output_file = session.script(LINPEAS_URL)

        if arguments.ai:
            assert len(api_key) > 10

            with open(output_file, "r") as file:
                content = file.read()
                # Preprocessing ;)
                processed_report = preprocess_linpeas(content)

            client = OpenAI(api_key=api_key)
            stream = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a helpful assistant helping me to perform penetration test to protect the systems",
                    },
                    {"role": "user", "content": f"{prompt}\n\n\n {processed_report}"},
                ],
                stream=True,
            )

            print("\n═════════════════ chatGPT analysis START ════════════════")
            for chunk in stream:
                # el streaming devuelve fragmentos; escribimos al stdout
                if chunk.choices[0].delta.content:
                    sys.stdout.write(chunk.choices[0].delta.content)
                    sys.stdout.flush()
            print("\n═════════════════ chatGPT analysis END ════════════════")
