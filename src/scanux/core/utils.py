"""
Utility functions for scanux
"""

def format_size(size_in_bytes: int) -> str:
    """
    Format a size in bytes to a human readable string
    
    Args:
        size_in_bytes: Size in bytes
        
    Returns:
        str: Formatted size string (e.g. '1.23 GB')
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.2f} PB" 