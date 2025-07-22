import click

import pdb
from private_search_set.main import PrivateSearchSet

@click.pass_context
def ingest_stdin(ctx):
    pss = ctx.obj
    click.echo("Ingesting stdin to PSS file.")
    pss.ingest_stdin(ctx.params["bf"], ctx.params["timeseries"], ctx.params["debug"])
    pss.write_to_files(ctx.params["pss_home"], ctx.params["bf"])

@click.pass_context
def check_stdin(ctx):
    pss = ctx.obj
    pss.check_stdin(ctx.params["bf"], ctx.params["timeseries"], ctx.params["debug"])

@click.command()
@click.option('--pss-home', required=True, type=click.Path(exists=False) , help='PSS working folder.')
@click.option('--json-file', required=False, type=click.Path(exists=True), help='Path to the PSS JSON template file.')
@click.option('--ingest/--check', required=True, type=click.BOOL , help='ingest or check stdin into/against PSS files')
@click.option('--bf', required=False, is_flag=True, default=False, help='check only bloom filter/ingest only bloom filter')
@click.option('--timeseries', required=False, is_flag=True, default=False, help='ingest in new bloomfilter/check all bloomfilter')
@click.option('--password', required=False, type=click.STRING , help='specify password for HMAC operations')
@click.option('--debug/--no-debug', default=False, help='print debug information')
@click.pass_context
def cli(ctx, json_file, pss_home, ingest, password, bf, timeseries, debug):
    # If a json-file with PSS metadata is provided, load the PSS from the JSON file
    # set the key if provided
    if json_file:
        if timeseries:
            click.echo("Using a template with timeseries is not possible.")
            exit(2)
        try:
            ctx.obj = PrivateSearchSet.load_from_json_specs(json_file, password, debug)
        except ValueError as e:
            click.echo(e)
            exit(1)
    # If pss_home is provided, load the PSS from the files in the folder
    # set the key if provided
    elif pss_home:
        try:
            ctx.obj = PrivateSearchSet.load_from_pss_home(pss_home, password, debug)
        except ValueError as e:
            click.echo(e)
            exit(1)
    if ingest:
        try:
            ingest_stdin()
        except ValueError as e:
            click.echo(e)
            exit(1)
    else:
        try:
            check_stdin()
        except ValueError as e:
            click.echo(e)
            exit(1)
    pass

def main():
    cli(obj={})
