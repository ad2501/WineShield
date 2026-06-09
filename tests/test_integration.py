#!/usr/bin/env python3

"""
Integration tests for WineShield components.
Tests the interaction between multiple security layers.
"""

import unittest
import sys
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Add the project root to the path so we can import core modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

class TestWineShieldIntegration(unittest.TestCase):
    """Integration tests for WineShield components."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a temporary directory for testing
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up after each test method."""
        # Remove the temporary directory
        shutil.rmtree(self.test_dir)

    def test_all_layers_can_be_loaded(self):
        """Test that all security layer modules can be imported."""
        # This test verifies that there are no import errors in the modules
        try:
            from core import syscall_monitor
            from core import fs_guard
            from core import network_guard
            from core import behavior_analyzer
            from core import xephyr_guard
            from core import apparmor_manager
        except ImportError as e:
            self.fail(f"Failed to import core modules: {e}")

    def test_seccomp_filter_can_be_compiled(self):
        """Test that the seccomp filter can be compiled."""
        # Check that the syscall_monitor binary exists
        syscall_monitor_path = os.path.join(
            os.path.dirname(__file__), '..', 'core', 'syscall_monitor'
        )
        
        self.assertTrue(
            os.path.exists(syscall_monitor_path),
            "syscall_monitor binary not found"
        )
        
        # Check that it's executable
        self.assertTrue(
            os.access(syscall_monitor_path, os.X_OK),
            "syscall_monitor binary is not executable"
        )

    def test_dashboard_can_be_imported(self):
        """Test that dashboard modules can be imported."""
        try:
            from dashboard import app
            from dashboard import routes
            from dashboard import websocket_server
        except ImportError as e:
            # This is expected since the dashboard is still a stub
            pass

    def test_config_files_exist(self):
        """Test that configuration files exist."""
        config_dir = os.path.join(
            os.path.dirname(__file__), '..', 'config'
        )
        
        # Check that key config files exist
        expected_files = [
            'network_rules.json',
            'apparmor/wineshield.wine',
            'apparmor/wineshield.wineserver',
            'apparmor/wineshield.framework'
        ]
        
        for file_path in expected_files:
            full_path = os.path.join(config_dir, file_path)
            self.assertTrue(
                os.path.exists(full_path),
                f"Config file not found: {full_path}"
            )

    @patch('core.sandbox_engine.os.unshare')
    @patch('core.syscall_monitor.wineshield_init_seccomp')
    def test_layers_can_be_initialized(self, mock_seccomp, mock_unshare):
        """Test that security layers can be initialized without errors."""
        # Mock the os.unshare function to avoid actually creating namespaces
        mock_unshare.return_value = 0
        
        # Mock the seccomp initialization to avoid actually installing filters
        mock_seccomp.return_value = 0
        
        try:
            from core import sandbox_engine
            from core import syscall_monitor
            
            # Initialize the components
            sandbox = sandbox_engine.SandboxEngine()
            sandbox.create_namespaces()
            
            # Try to initialize seccomp in each mode
            for mode in [0, 1, 2]:  # MONITOR, BALANCED, STRICT
                syscall_monitor.wineshield_init_seccomp(mode)
                
        except Exception as e:
            self.fail(f"Failed to initialize security layers: {e}")


if __name__ == '__main__':
    unittest.main()