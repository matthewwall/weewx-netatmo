# $Id: install.py 1484 2016-04-25 16:20:31Z mwall $
# installer for netatmo driver
# Copyright 2015 Matthew Wall

from setup import ExtensionInstaller

def loader():
    return NetatmoInstaller()

class NetatmoInstaller(ExtensionInstaller):
    def __init__(self):
        super(NetatmoInstaller, self).__init__(
            version="0.3",
            name='netatmo',
            description='Driver for netatmo weather stations.',
            author="Matthew Wall",
            author_email="mwall@users.sourceforge.net",
            files=[('bin/user', ['bin/user/netatmo.py'])]
            )
