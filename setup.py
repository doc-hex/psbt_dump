# based on <http://click.pocoo.org/5/setuptools/#setuptools-integration>
#
# To use this, install with:
#
#   pip install --editable .

from setuptools import setup

setup(
    name='psbt_dump',
    version='1.0',
    py_modules=[],
    python_requires='>3.5.2',
    install_requires=[
        'Click',
        'pycoin == 0.80'
    ],
    entry_points='''
        [console_scripts]
        psbt_dump=psbt_dump:dump
    ''',
)

