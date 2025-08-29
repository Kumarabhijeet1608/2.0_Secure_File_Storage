import os
import mimetypes
from typing import Tuple

def is_media_file(filename: str) -> Tuple[bool, str]:
    """
    Check if a file is a media file based on its extension
    
    Args:
        filename (str): The filename to check
        
    Returns:
        Tuple[bool, str]: (is_media, file_extension)
    """
    if not filename:
        return False, ""
    
    # Get file extension
    _, extension = os.path.splitext(filename.lower())
    
    # Define media file extensions
    media_extensions = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',  # Images
        '.mp3', '.mp4', '.wav', '.flac', '.aac', '.ogg', '.wma',    # Audio
        '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.m4v',    # Video
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'   # Documents
    }
    
    is_media = extension in media_extensions
    
    return is_media, extension

def get_file_type(filename: str) -> str:
    """
    Get the general file type category
    
    Args:
        filename (str): The filename to categorize
        
    Returns:
        str: File type category
    """
    if not filename:
        return "unknown"
    
    _, extension = os.path.splitext(filename.lower())
    
    # Categorize file types
    if extension in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}:
        return "image"
    elif extension in {'.mp3', '.mp4', '.wav', '.flac', '.aac', '.ogg', '.wma'}:
        return "audio"
    elif extension in {'.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.m4v'}:
        return "video"
    elif extension in {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}:
        return "document"
    elif extension in {'.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml'}:
        return "text"
    elif extension in {'.zip', '.rar', '.7z', '.tar', '.gz'}:
        return "archive"
    else:
        return "unknown"

def is_safe_file(filename: str) -> bool:
    """
    Check if a file extension is considered safe for upload
    
    Args:
        filename (str): The filename to check
        
    Returns:
        bool: True if file is safe, False otherwise
    """
    if not filename:
            return False
            
    # Define dangerous file extensions
    dangerous_extensions = {
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js',
        '.jar', '.msi', '.dll', '.sys', '.drv', '.ocx', '.cpl'
    }
    
    _, extension = os.path.splitext(filename.lower())
    
    return extension not in dangerous_extensions
    