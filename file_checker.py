def is_media_file(file_path):
    media_extensions = ['mp3', 'mp4', 'wav', 'avi', 'mov', 'mkv', 'flv', 'jpeg', 'jpg', 'png', 'gif', 'bmp']
    file_extension = file_path.split('.')[1]
    print(file_extension)
    if file_extension in media_extensions:
        return [True, file_extension]
    else: 
        return [False, None]


    

    