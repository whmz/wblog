# Watch for File Changes
Hexo can watch for file changes and regenerate files immediately. Hexo will compare the SHA1 checksum of your files and only write if file changes are detected.

$ hexo generate --watch

# Deploy After Generating
To deploy after generating, you can run one of the following commands. There is no difference between the two.

$ hexo generate --deploy
$ hexo deploy --generate
