#!/bin/bash
#
# Copyright (C) 2025 ZqinKing <ZqinKing23@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY and FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# 定义镜像和容器名称，方便管理
IMAGE_NAME="pcap-scanner"
CONTAINER_NAME="pcap-scanner-temp-builder"
OUTPUT_BINARY="pcap_scanner"

# 脚本出错时立即退出
set -e

echo "--- [1/5] 正在清理旧的 Docker 镜像 (如果存在)... ---"
# 检查镜像是否存在，如果存在则删除
if [[ "$(docker images -q $IMAGE_NAME:latest 2> /dev/null)" != "" ]]; then
  echo "找到旧的镜像 '$IMAGE_NAME'，正在删除..."
  docker rmi -f $IMAGE_NAME:latest
else
  echo "未找到旧的镜像 '$IMAGE_NAME'，跳过删除。"
fi

echo "--- [2/5] 正在使用最新的代码构建 Docker 镜像... ---"
# 生成版本字符串，格式为 vYY.MM.DD
VERSION=$(date +v%y.%m.%d)
echo "正在构建版本: $VERSION"
# 添加 --pull=false 避免强制拉取基础镜像，减少 Docker Hub 调用频率
docker build --build-arg BUILD_VERSION=$VERSION -t $IMAGE_NAME --pull=false .

echo "--- [3/5] 正在创建临时容器以提取编译产物... ---"
# --rm 标志会在容器停止后自动删除它，但为了安全起见，我们手动创建和删除
# 先确保同名容器不存在
docker rm $CONTAINER_NAME > /dev/null 2>&1 || true
CONTAINER_ID=$(docker create --name $CONTAINER_NAME $IMAGE_NAME)

echo "--- [4/5] 正在从容器拷贝二进制文件 '$OUTPUT_BINARY' 到当前目录... ---"
docker cp "$CONTAINER_ID:/app/$OUTPUT_BINARY" .

echo "--- [5/5] 正在清理临时容器... ---"
docker rm $CONTAINER_ID

echo "--- 构建流程成功完成！ ---"
echo "二进制文件 '$OUTPUT_BINARY' 已准备就绪，您现在可以运行它。"
ls -l $OUTPUT_BINARY
