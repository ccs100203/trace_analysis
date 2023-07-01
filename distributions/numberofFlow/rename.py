import os, sys

dir_list = os.listdir(os.getcwd())

cnt = 0
for dir in dir_list:
    if os.path.isdir(dir):
        filename_list = os.listdir(dir)
        for filename in filename_list:
            input_file = os.path.join('.', dir, filename)

            ll = filename.split('-1.1-')
            num = ll[1].split('-')[0]
            suffix = filename.split('fixFlowPkt-')[1]
            new_filename = f'{ll[0]}-1.1-numberofFlow-{num}x-{suffix}'

            output_file = os.path.join('.', dir, new_filename)
            cnt += 1
            print(input_file)
            print(output_file)
            os.rename(input_file, output_file)
            print()

print(cnt)
