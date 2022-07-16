import json
import pathlib
import copy
import os

from subprocess import Popen, PIPE
from multiprocessing import Pool
from typing import List


class Compiler:
    """Futag Compiler"""

    # def __init__(self, output_path: str, json_file: str, target_project_archive: str, futag_package_path: str, library_root: str):
    def __init__(self, futag_package_path: str, library_root: str, build_dir=None, install_dir=None):
        """
        Parameters
        ----------
        futag_package_path: str
            path to the futag package (with binaries, scripts, etc)
        library_root: str
            path to the library root
        build_dir: str
            path to the build directory
        install_dir: str
            path to the install directory
        """

        # self.target_project_archive = target_project_archive
        self.futag_package_path = futag_package_path
        self.library_root = library_root
        if not build_dir:
            self.build_dir = build_dir
        else:
            self.build_dir = "build"

        if not install_dir:
            self.install_dir = install_dir
        else:
            self.install_dir = "install"

        if pathlib.Path(self.futag_package_path).absolute().exists() and (pathlib.Path(self.futag_package_path) / "bin/clang").absolute().exists():
            self.futag_package_path = pathlib.Path(
                self.futag_package_path).absolute()
        else:
            raise ValueError('Incorrect path to FUTAG package')

        if pathlib.Path(self.library_root).absolute().exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            raise ValueError('Incorrect path to the library root')

        if not (self.build_dir).exists():
            (self.build_dir).mkdir(parents=True, exist_ok=True)

        if not (self.install_dir).exists():
            (self.install_dir).mkdir(parents=True, exist_ok=True)

    def auto_build(self):

    def build_cmake(self):

    def build_configure(self):
        
