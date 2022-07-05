from setuptools import setup

setup(
   name='futag',
   version='0.1',
   author='Futag-team of ISP RAS',
   author_email='thientc@ispras.ru',
   packages=['futag'],
   scripts=[],
   url='https://gitlab.ispras.ru',
   license='LICENSE',
   description='Futag tools for creating fuzz targets of software library',
   long_description=open('README.md').read(),
   install_requires=[
       "pathlib",
       "argparse",
   ],
)