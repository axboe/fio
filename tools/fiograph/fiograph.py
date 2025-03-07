#!/usr/bin/env python3
import uuid
import time
import errno
from graphviz import Digraph
import argparse
import configparser
import os

config_file = None
fio_file = None


def get_section_option(section_name, option_name, default=None):
    global fio_file
    if fio_file.has_option(section_name, option_name):
        return fio_file[section_name][option_name]
    return default


def get_config_option(section_name, option_name, default=None):
    global config_file
    if config_file.has_option(section_name, option_name):
        return config_file[section_name][option_name]
    return default


def get_header_color(keyword='fio_jobs', default_color='black'):
    return get_config_option(keyword, 'header_color', default_color)


def get_shape_color(keyword='fio_jobs', default_color='black'):
    return get_config_option(keyword, 'shape_color', default_color)


def get_text_color(keyword='fio_jobs', default_color='black'):
    return get_config_option(keyword, 'text_color', default_color)


def get_cluster_color(keyword='fio_jobs', default_color='gray92'):
    return get_config_option(keyword, 'cluster_color', default_color)


def get_header(keyword='fio_jobs'):
    return get_config_option(keyword, 'header')


def get_shape(keyword='fio_jobs'):
    return get_config_option(keyword, 'shape', 'box')


def get_style(keyword='fio_jobs'):
    return get_config_option(keyword, 'style', 'rounded')


def get_cluster_style(keyword='fio_jobs'):
    return get_config_option(keyword, 'cluster_style', 'filled')


def get_specific_options(engine):
    if not engine:
        return ''
    return get_config_option('ioengine_{}'.format(engine), 'specific_options', '').split(' ')


def render_option(section, label, display, option, color_override=None):
    # These options are already shown with graphical helpers, no need to report them directly
    skip_list = ['size', 'stonewall', 'runtime', 'time_based',
                 'numjobs', 'wait_for', 'wait_for_previous']
    # If the option doesn't exist or if a special handling is already done
    # don't render it, just return the current state
    if option in skip_list or option not in section:
        return label, display
    display = option
    if section[option]:
        display = '{} = {}'.format(display, section[option])

    # Adding jobs's options into the box, darkgreen is the default color
    if color_override:
        color = color_override
    else:
        color = get_text_color(option, get_text_color('fio_jobs', 'darkgreen'))
    label += get_config_option('fio_jobs',
                               'item_style').format(color, display)
    return label, display


def render_options(fio_file, section_name):
    """Render all options of a section."""
    display = section_name
    section = fio_file[section_name]

    # Add a multiplier to the section_name if numjobs is set
    numjobs = int(get_section_option(section_name, 'numjobs', '1'))
    if numjobs > 1:
        display = display + \
            get_style('numjobs').format(
                get_text_color('numjobs'), numjobs)

    # Header of the box
    label = get_config_option('fio_jobs', 'title_style').format(display)

    # Let's parse all the options of the current fio thread
    # Some needs to be printed on top or bottom of the job to ease the read
    to_early_print = ['exec_prerun', 'ioengine']
    to_late_print = ['exec_postrun']

    # Let's print the options on top of the box
    for early_print in to_early_print:
        label, display = render_option(
            section, label, display, early_print)

    current_io_engine = get_section_option(
        section_name, 'ioengine', None)
    if current_io_engine:
        # Let's print all specifics options for this engine
        for specific_option in sorted(get_specific_options(current_io_engine)):
            label, display = render_option(
                section, label, display, specific_option, get_config_option('ioengine', 'specific_options_color'))

    # Let's print generic options sorted by name
    for option in sorted(section):
        if option in to_early_print or option in to_late_print or option in get_specific_options(current_io_engine):
            continue
        label, display = render_option(section, label, display, option)

    # let's print options on the bottom of the box
    for late_print in to_late_print:
        label, display = render_option(
            section, label, display, late_print)

    # End of the box content
    label += '</table>>'
    return label


def render_section(current_graph, fio_file, section_name, label):
    """Render the section."""
    attr = None
    section = fio_file[section_name]

    # Let's render the box associated to a job
    current_graph.node(section_name, label,
                       shape=get_shape(),
                       color=get_shape_color(),
                       style=get_style())

    # Let's report the duration of the jobs with a self-loop arrow
    if 'runtime' in section and 'time_based' in section:
        attr = 'runtime={}'.format(section['runtime'])
    elif 'size' in section:
        attr = 'size={}'.format(section['size'])
    if attr:
        current_graph.edge(section_name, section_name, attr)


def create_sub_graph(name):
    """Return a new graph."""
    # We need to put 'cluster' in the name to ensure graphviz consider it as a cluster
    cluster_name = 'cluster_' + name
    # Unset the main graph labels to avoid a recopy in each subgraph
    attr = {}
    attr['label'] = ''
    new_graph = Digraph(name=cluster_name, graph_attr=attr)
    new_graph.attr(style=get_cluster_style(),
                   color=get_cluster_color())
    return new_graph


def create_legend():
    """Return a legend."""
    html_table = "<<table border='0' cellborder='1' cellspacing='0' cellpadding='4'>"
    html_table += '<tr><td COLSPAN="2"><b>Legend</b></td></tr>'
    legend_item = '<tr> <td>{}</td> <td><font color="{}">{}</font></td></tr>"'
    legend_bgcolor_item = '<tr><td>{}</td><td BGCOLOR="{}"></td></tr>'
    html_table += legend_item.format('numjobs',
                                     get_text_color('numjobs'), 'x numjobs')
    html_table += legend_item.format('generic option',
                                     get_text_color(), 'generic option')
    html_table += legend_item.format('ioengine option',
                                     get_text_color('ioengine'), 'ioengine option')
    html_table += legend_bgcolor_item.format('job', get_shape_color())
    html_table += legend_bgcolor_item.format(
        'execution group', get_cluster_color())
    html_table += '</table>>'
    legend = Digraph('html_table')
    legend.node('legend', shape='none', label=html_table)
    return legend


def fio_to_graphviz(filename, format):
    """Compute the graphviz graph from the fio file."""

    # Let's read the fio file
    global fio_file
    fio_file = configparser.RawConfigParser(
        allow_no_value=True,
        default_section="global",
        inline_comment_prefixes="'#', ';'")
    fio_file.read(filename)

    # Prepare the main graph object
    # Let's define the header of the document
    attrs = {}
    attrs['labelloc'] = 't'
    attrs['label'] = get_header().format(
        get_header_color(), os.path.basename(filename))
    main_graph = Digraph(engine='dot', graph_attr=attrs, format=format)

    # Let's add a legend
    main_graph.subgraph(create_legend())

    # By default all jobs are run in parallel and depends on "global"
    depends_on = fio_file.default_section

    # The previous section is by default the global section
    previous_section = fio_file.default_section

    current_graph = main_graph

    # The first job will be a new execution group
    new_execution_group = True

    # Let's iterate on all sections to create links between them
    for section_name in fio_file.sections():
        # The current section
        section = fio_file[section_name]

        # If the current section is waiting the previous job
        if ('stonewall' or 'wait_for_previous') in section:
            # let's remember what was the previous job we depend on
            depends_on = previous_section
            new_execution_group = True
        elif 'wait_for' in section:
            # This sections depends on a named section pointed by wait_for
            depends_on = section['wait_for']
            new_execution_group = True

        if new_execution_group:
            # Let's link the current graph with the main one
            main_graph.subgraph(current_graph)
            # Let's create a new graph to represent all the incoming jobs running at the same time
            current_graph = create_sub_graph(section_name)

        # Let's render the current section in its execution group
        render_section(current_graph, fio_file, section_name,
                       render_options(fio_file, section_name))

        # Let's trace the link between this job and the one it depends on
        # If we depend on 'global', we can avoid doing adding an arrow as we don't want to see 'global'
        if depends_on != fio_file.default_section:
            current_graph.edge(depends_on, section_name)

        # The current section become the parent of the next one
        previous_section = section_name

        # We are by default in the same execution group
        new_execution_group = False

    # The last subgraph isn't rendered yet
    main_graph.subgraph(current_graph)

    # Let's return the main graphviz object
    return main_graph


def setup_commandline():
    "Prepare the command line."
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', action='store',
                        type=str,
                        required=True,
                        help='the fio file to graph')
    parser.add_argument('--output', action='store',
                        type=str,
                        help='the output filename')
    parser.add_argument('--format', action='store',
                        type=str,
                        default='png',
                        help='the output format (see https://graphviz.org/docs/outputs/)')
    parser.add_argument('--view', action='store_true',
                        default=False,
                        help='view the graph')
    parser.add_argument('--keep', action='store_true',
                        default=False,
                        help='keep the graphviz script file')
    parser.add_argument('--config', action='store',
                        type=str,
                        help='the configuration filename')
    args = parser.parse_args()
    return args


def main():
    global config_file
    args = setup_commandline()

    if args.config is None:
        if os.path.exists('fiograph.conf'):
            config_filename = 'fiograph.conf'
        else:
            config_filename = os.path.join(os.path.dirname(__file__), 'fiograph.conf')
            if not os.path.exists(config_filename):
                raise FileNotFoundError("Cannot locate configuration file")
    else:
        config_filename = args.config
    config_file = configparser.RawConfigParser(allow_no_value=True)
    config_file.read(config_filename)

    temp_filename = uuid.uuid4().hex
    image_filename = fio_to_graphviz(args.file, args.format).render(temp_filename, view=args.view)

    output_filename_stub = args.file
    if args.output:
        output_filename = args.output
    else:
        if output_filename_stub.endswith('.fio'):
            output_filename_stub = output_filename_stub[:-4]
        output_filename = image_filename.replace(temp_filename, output_filename_stub)
    if args.view:
        time.sleep(1)
        # allow time for the file to be opened before renaming it
    os.rename(image_filename, output_filename)

    if not args.keep:
        os.remove(temp_filename)
    else:
        os.rename(temp_filename, output_filename_stub + '.gv')


main()
