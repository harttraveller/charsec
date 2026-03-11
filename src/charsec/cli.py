from importlib import metadata

from cyclopts import App

from charsec import lib

project = "charsec"

app = App(name=project, version=metadata.version(project))

app.command(lib.extract)
app.command(lib.inject)
app.command(lib.remove)
app.command(lib.run)
app.command(lib.scan)
