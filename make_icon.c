#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push,1)
typedef struct { uint16_t idReserved; uint16_t idType; uint16_t idCount; } ICONDIR;
typedef struct { uint8_t bWidth; uint8_t bHeight; uint8_t bColorCount; uint8_t bReserved; uint16_t wPlanes; uint16_t wBitCount; uint32_t dwBytesInRes; uint32_t dwImageOffset; } ICONDIRENTRY;
typedef struct { uint32_t biSize; int32_t biWidth; int32_t biHeight; uint16_t biPlanes; uint16_t biBitCount; uint32_t biCompression; uint32_t biSizeImage; int32_t biXPelsPerMeter; int32_t biYPelsPerMeter; uint32_t biClrUsed; uint32_t biClrImportant; } BITMAPINFOHEADER;
#pragma pack(pop)

int main(){
    const int W=32, H=32;
    uint32_t xorSize = W*H*4;
    uint32_t andStride = ((W + 31) / 32) * 4; // 1bpp padded to 32 bits
    uint32_t andSize = andStride * H;
    uint32_t dibSize = sizeof(BITMAPINFOHEADER) + xorSize + andSize;
    uint32_t fileSize = sizeof(ICONDIR) + sizeof(ICONDIRENTRY) + dibSize;

    FILE *fp = fopen("app.ico","wb");
    if(!fp){ perror("open"); return 1; }

    ICONDIR dir = {0,1,1};
    ICONDIRENTRY ent; memset(&ent,0,sizeof(ent));
    ent.bWidth=W; ent.bHeight=H; ent.bColorCount=0; ent.bReserved=0; ent.wPlanes=1; ent.wBitCount=32; ent.dwBytesInRes=dibSize; ent.dwImageOffset=sizeof(ICONDIR)+sizeof(ICONDIRENTRY);
    fwrite(&dir,1,sizeof(dir),fp);
    fwrite(&ent,1,sizeof(ent),fp);

    BITMAPINFOHEADER bih; memset(&bih,0,sizeof(bih));
    bih.biSize=40; bih.biWidth=W; bih.biHeight=H*2; // height includes XOR+AND
    bih.biPlanes=1; bih.biBitCount=32; bih.biCompression=0; bih.biSizeImage=xorSize;
    fwrite(&bih,1,sizeof(bih),fp);

    // XOR bitmap (BGRA, bottom-up)
    uint32_t px[W*H]; memset(px,0,sizeof(px));
    uint32_t blue = 0xFF4D64F8; // ARGB
    // draw bars
    int leftX=4, midX=16, rightX=26-2; // adjust
    int leftW=8, midW=8, rightW=8;
    int leftH=14, midH=20, rightH=28;
    for(int y=0;y<H;y++){
        for(int x=0;x<W;x++){
            px[y*W+x]=0x00000000; // transparent
        }
    }
    for(int yy=H-leftH; yy<H; ++yy){ for(int xx=leftX; xx<leftX+leftW; ++xx){ if(xx>=0&&xx<W&&yy>=0&&yy<H) px[yy*W+xx]=blue; } }
    for(int yy=H-midH; yy<H; ++yy){ for(int xx=midX; xx<midX+midW; ++xx){ if(xx>=0&&xx<W&&yy>=0&&yy<H) px[yy*W+xx]=blue; } }
    for(int yy=H-rightH; yy<H; ++yy){ for(int xx=rightX; xx<rightX+rightW; ++xx){ if(xx>=0&&xx<W&&yy>=0&&yy<H) px[yy*W+xx]=blue; } }

    // write bottom-up BGRA (Windows DIB stores BGRA)
    for(int y=H-1; y>=0; --y){
        for(int x=0; x<W; ++x){
            uint32_t a = (px[y*W+x]>>24)&0xFF;
            uint32_t r = (px[y*W+x]>>16)&0xFF;
            uint32_t g = (px[y*W+x]>>8)&0xFF;
            uint32_t b = (px[y*W+x])&0xFF;
            uint8_t bgra[4] = { (uint8_t)b, (uint8_t)g, (uint8_t)r, (uint8_t)a };
            fwrite(bgra,1,4,fp);
        }
    }

    // AND mask (opaque = 0)
    for(int y=0; y<H; ++y){
        // 32 pixels -> 32 bits, 0 for opaque
        uint32_t row = 0x00000000;
        fwrite(&row,1,andStride,fp);
    }

    fclose(fp);
    return 0;
}

