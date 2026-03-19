from setuptools import setup

setup(
   name='futag',
   version='3.0.1',
   author='Futag-team of ISP RAS',
   author_email='thientcgithub@gmail.com',
   packages=['futag'],
   package_dir={'futag': 'src/futag'},
   scripts=[],
   url='https://github.com/ispras/Futag',
   project_urls={
       'Documentation': 'https://github.com/ispras/Futag/tree/main/docs',
       'Source': 'https://github.com/ispras/Futag/tree/main/src/python/futag-package',
       'Bug Tracker': 'https://github.com/ispras/Futag/issues',
   },
   license='LICENSE',
   description='Futag - Fuzz target Automated Generator for software libraries',
   long_description=open('README.md').read(),
   long_description_content_type='text/markdown',
   classifiers=[
       'Development Status :: 4 - Beta',
       'Intended Audience :: Developers',
       'Topic :: Software Development :: Testing',
       'Programming Language :: Python :: 3',
       'Programming Language :: Python :: 3.8',
       'Programming Language :: Python :: 3.9',
       'Programming Language :: Python :: 3.10',
       'Programming Language :: Python :: 3.11',
       'Programming Language :: Python :: 3.12',
   ],
   python_requires='>=3.8',
   install_requires=[
       "pathlib",
       "argparse",
   ],
   extras_require={
       "test": ["pytest>=7.0"],
   },
)