"""
EchoCTF module for Penelope
by DystopianRescuer
"""


class claim_flags(Module):
    enabled = True
    category = "ETSCTF"
    on_session_start = False
    on_session_end = False

    # Static session for reutilization purposes
    web_session = None

    def run(session, args):
        """
        Flag colector for ETSCTF-based CTFs
        """
        import requests
        import re
        import html

        if not claim_flags.web_session:
            claim_flags.web_session = requests.Session()

        # web data
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0",
            "Accept": "text/html, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
        }
        web_session = claim_flags.web_session
        web_session.headers.update(headers)

        # Dada la hoja html, busca y devuelve el csrf token embebido
        def get_csrf_token(html: str):
            return re.search(
                r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
                html,
                re.I,
            ).group(1)

        # Inicia y guarda la sesión en la plataforma
        def login():
            logger.info("Iniciando sesión...")
            endpoint = "/login"
            req = web_session.get(ctf_rootpage + endpoint)
            payload = {
                "_csrf-red": get_csrf_token(req.text),
                "LoginForm[username]": ctf_username,
                "LoginForm[password]": ctf_password,
                "LoginForm[rememberMe]": "1",
                "login-button": "",
            }
            response = web_session.post(
                ctf_rootpage + endpoint,
                data=payload,
                allow_redirects=False,
            )
            # Si conseguí la respuesta que busco, entonces guardo la sesión
            if response.status_code == 302:
                logger.info("Inicio de sesión exitoso")
            else:
                logger.error(
                    f"No se pudo iniciar sesión. {'Credenciales inválidas' if 'Incorrect username or password' in response.text else 'Error desconocido'}"
                )

        # Idealmente usado antes de cada operación a la plataforma, para buscar reciclar la sesión guardada, si es que existe
        def check_if_active_session():
            if not web_session or not web_session.cookies:
                return False

            logger.info("Checando si la sesión sigue viva")
            endpoint = "/"
            req = web_session.get(ctf_rootpage + endpoint)
            html = req.text
            return "/login" not in html

        # Uses de one-lines to get all flags on the system
        def search_flags():
            one_liner = r"""P='ETSCTF_[0-9a-fA-F]{32}';{ for F in env /etc/passwd /proc/1/environ /etc/shadow /root/; do case $F in env) env ;; /proc/1/environ) tr '\0' '\n' <"$F" 2>/dev/null ;; /root/) ls -A "$F" 2>/dev/null ;; *) cat "$F" 2>/dev/null ;; esac; done; find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /etc \) -prune -o -type f -print0 2>/dev/null | xargs -0 -r grep -aHoE "$P" 2>/dev/null | awk -F: '{print $2}'; find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /etc \) -prune -o -name '*ETSCTF_*' -print 2>/dev/null | xargs -r -n1 -I{} basename {} 2>/dev/null; } | grep -oE "$P" | sed '/^$/d' | awk '!seen[$0]++'"""
            logger.info("Buscando banderas...")
            flags = session.exec(one_liner, timeout=20, agent_typing=True, value=True)
            if flags:
                flags = flags.splitlines()
                logger.info(f"Se encontraron {len(flags)} banderas")
                for flag in flags:
                    logger.info(f"Reclamando bandera {flag}")
                    claim(flag)
            else:
                logger.info("No se encontraron banderas")

        # Reclama la bandera en la plataforma
        def claim(flag: str):
            if not check_if_active_session():
                logger.error(
                    "Sesión inválida, no se pudo cobrar la bandera. Intenta de nuevo."
                )
                return

            csrf_req = web_session.get(ctf_rootpage + "/dashboard")
            claim_endpoint = "/claim"
            payload = {
                "_csrf-red": get_csrf_token(csrf_req.text),
                "hash": flag,
            }
            req = web_session.post(
                ctf_rootpage + claim_endpoint,
                data=payload,
                timeout=15,
            )
            if not req.status_code == 200:
                logger.error(
                    f"Ocurrió un error al cobrar bandera\n {payload}\n\nStatus code: {req.status_code}. \nContent: {req.content}"
                )
                return

            notifications = check_notifications()

            # Mandar error si no hay respuesta, pero tambien si la respuesta es negativa
            if notifications:
                logger.info(f"Respuesta: {notifications[0]}")
            else:
                logger.error(
                    "No hubo respuesta del servicio, verifica si la bandera fue cobrada"
                )

        # Checa notificaciones pendientes, usado para ver si las banderas reclamadas han sido validadas
        def check_notifications():
            if not check_if_active_session():
                logger.error("No active session")
                return

            endpoint = "/dashboard"

            r = web_session.get(ctf_rootpage + endpoint)
            # checar status
            txt = r.text

            # buscar mensajes tanto "message": "..." como 'message': '...'
            dbl = re.findall(
                r'"message"\s*:\s*"((?:\\.|[^"\\])*)"', txt, flags=re.DOTALL
            )
            sng = re.findall(
                r"'message'\s*:\s*'((?:\\.|[^'\\])*)'", txt, flags=re.DOTALL
            )
            raw_msgs = dbl + sng

            # si no encontró, intentar dentro de bloques $.notify(...)
            if not raw_msgs:
                for blk in re.findall(
                    r"\$\.notify\s*\(\s*(\{.*?\})\s*,", txt, flags=re.DOTALL
                ):
                    m = re.search(r'"message"\s*:\s*"((?:\\.|[^"\\])*)"', blk)
                    if m:
                        raw_msgs.append(m.group(1))
                        continue
                    m = re.search(r"'message'\s*:\s*'((?:\\.|[^'\\])*)'", blk)
                    if m:
                        raw_msgs.append(m.group(1))

            def _unescape(s: str) -> str:
                try:
                    s2 = bytes(s, "utf-8").decode("unicode_escape")
                except Exception:
                    s2 = s.replace(r"\"", '"').replace(r"\'", "'")
                    s2 = html.unescape(s2)
                # quitar tags html
                return re.sub(r"<[^>]+>", "", s2)

            return [_unescape(m).strip() for m in raw_msgs]

        if not check_if_active_session():
            login()

        search_flags()
