{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  # nativeBuildInputs автоматически прокидывает pkg-config и пути к зависимостям
  nativeBuildInputs = [
    pkgs.protobuf
    pkgs.protoc-gen-go
    pkgs.protoc-gen-go-grpc
  ];

  shellHook = ''
    # Так как .dev отсутствует, берем include напрямую из основного пакета
    export PROTO_INCLUDE="${pkgs.protobuf}/include"
    echo "Protobuf environment ready!"
    echo "PROTO_INCLUDE is set to: $PROTO_INCLUDE"
  '';
}
