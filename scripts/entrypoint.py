import click


@click.group(context_settings={
    "help_option_names": ["-h", "--help"],
})
def cli():
    pass


@cli.command()
def init():
    """Initialize data.
    """
    import initializer
    initializer.initialize()


@cli.command()
def ldap2cb():
    """Convert data from LDAP to Couchbase.
    """
    import migrator
    migrator.migrate()


if __name__ == "__main__":
    cli()
