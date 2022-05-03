# based on <http://click.pocoo.org/5/setuptools/#setuptools-integration>
#
# To use this, install with:
#
#   pip install --editable .

from setuptools import setup, find_packages

VERSION = '1.5'

with open('README.md', 'rt') as fd:
    desc = fd.read()

if __name__ == '__main__':
    setup(
        name='psbt_dump',
        author='Coinkite Inc.',
        author_email='support@coinkite.com',
        description="Dump PSBT files to text with as few assumptions as possible",
        version=VERSION,
        packages=find_packages(),
        long_description=desc,
        long_description_content_type="text/markdown",
        url="https://github.com/doc-hex/psbt_dump",
        python_requires='>3.6.0',
        install_requires=[
            'Click',
            'pycoin == 0.80'
        ],
        entry_points='''
            [console_scripts]
            psbt_dump=psbt_dump:dump
        ''',
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ]
    )

