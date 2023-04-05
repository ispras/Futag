from setuptools import setup

setup(
   name='futag',
   version='2.0.1',
   author='Futag-team of ISP RAS',
   author_email='thientcgithub@gmail.com',
   packages=['futag'],
   scripts=[],
   url='https://github.com/ispras/Futag/tree/main/src/python/futag-package',
   license='LICENSE',
   description='Futag tools for creating fuzz targets of software library',
   long_description=open('README.md').read(),
   install_requires=[
       "pathlib",
       "argparse",
   ],
)