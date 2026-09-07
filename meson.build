# SPDX-License-Identifier: BSD-3-Clause

project(
    'pseudowire-etherip',
    'c',
    version: '0.1.0',
    license: 'BSD-3-Clause',
    default_options: ['warning_level=2', 'buildtype=release'],
    meson_version: '>= 0.61.2',
)

dpdk = dependency('libdpdk', version: '>= 24.11')

executable(
    'dpdk-pseudowire-etherip',
    'pseudowire_etherip.c',
    dependencies: dpdk,
    c_args: ['-DALLOW_EXPERIMENTAL_API'],
    install: true,
)

executable(
    'pestats',
    'pestats/main.c',
    install: true,
)
