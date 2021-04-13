pkgdatadir = join_paths(get_option('prefix'), get_option('datadir'), meson.project_name())
moduledir = join_paths(pkgdatadir, 'portscanner')
gnome = import('gnome')

gnome.compile_resources('portscanner',
  'portscanner.gresource.xml',
  gresource_bundle: true,
  install: true,
  install_dir: pkgdatadir,
)

python = import('python')

conf = configuration_data()
conf.set('PYTHON', python.find_installation('python3').path())
conf.set('VERSION', meson.project_version())
conf.set('localedir', join_paths(get_option('prefix'), get_option('localedir')))
conf.set('pkgdatadir', pkgdatadir)

configure_file(
  input: 'portscanner.in',
  output: 'portscanner',
  configuration: conf,
  install: true,
  install_dir: get_option('bindir')
)

portscanner_sources = [
  '__init__.py',
  'main.py',
  'window.py',
  'scanner.py',
  'ports.py',
  'portdata.py',
  'packets.py',
]

install_data(portscanner_sources, install_dir: moduledir)
