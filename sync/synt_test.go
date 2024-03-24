package sync

import (
	"io"
	"log"
	"os"
	"syscall"
	"testing"
)

// test to address the rejection of some blocks already seen by hnsd
func TestParser(t *testing.T) {
	syncdata := `
chain (217515): adding block: 0000000000000002f47cfbd4b44aa0a6c8107590c8aca9739a5a418b67fb20a6
chain (217515): tree_root 622b5b297bd0485239eaf794017de020c522feab109988b517453408b320c7f6 timestamp 1711243226 
chain (217515):   rejected: duplicate
peer 0 (107.152.33.71:44806): failed adding block: EDUPLICATE
chain (217515): adding block: 0000000000000001f8ef2ddc3fe93f73ba1bf3c5c0f002b3ce39fee1f2050328
chain (217515): tree_root 622b5b297bd0485239eaf794017de020c522feab109988b517453408b320c7f6 timestamp 1711244754 
chain (217515):   rejected: duplicate
peer 0 (107.152.33.71:44806): failed adding block: EDUPLICATE
chain (217515): adding block: 000000000000000397ecdb973332595c777c69952591cd137745bf1c3c9e2898
chain (217515): tree_root 28dc17c03924644b3da99ce8afbb434a9efb2312ff21b53bfeaeb38015dc51aa timestamp 1711286661 
chain (217515):   rejected: duplicate
peer 0 (107.152.33.71:44806): failed adding block: EDUPLICATE
chain (217515): adding block: 0000000000000002496db35faf8c3251d500653e00c2c4e378694b7b6bf40bc5
chain (217515): tree_root 28dc17c03924644b3da99ce8afbb434a9efb2312ff21b53bfeaeb38015dc51aa timestamp 1711287670 
chain (217515):   rejected: duplicate
peer 0 (107.152.33.71:44806): failed adding block: EDUPLICATE
chain (217504): adding block: 000000000000000123d5c937c585e608f2c25e03bf768206f2fc69609dac194c
chain (217504): tree_root 0e6c79be15eff6e80f83a991715a1f531cdefc7df4aa4d206095aa0202f36c5b timestamp 1711144096 
chain (217504):   rejected: duplicate
peer 1 (139.162.183.168:44806): failed adding block: EDUPLICATE
chain (217504): adding block: 00000000000000047622f5a5e97d39faafa729931a35b2d4ef01b2e96f5be054
chain (217504): tree_root 0e6c79be15eff6e80f83a991715a1f531cdefc7df4aa4d206095aa0202f36c5b timestamp 1711144297 
chain (217504):   rejected: duplicate
peer 1 (139.162.183.168:44806): failed adding block: EDUPLICATE
chain (217504): adding block: 000000000000000470951ccd613056c4eaa40890c03284cf26a560dd0ab2f567
chain (217504): tree_root 0e6c79be15eff6e80f83a991715a1f531cdefc7df4aa4d206095aa0202f36c5b timestamp 1711144398 
chain (217504):   rejected: duplicate
chain (217508): adding block: 00000000000000035f3b262d2f686610884ae4449854a7e01aad415d4a1c74d8
chain (217508): tree_root 28dc17c03924644b3da99ce8afbb434a9efb2312ff21b53bfeaeb38015dc51aa timestamp 1711285062 
chain (217509):   added to main chain
chain (217509):   new height: 217509
chain (217509): adding block: 0000000000000000e4cf104d2de322f9552e1ac4d7d2c7dc47bf08f92a82b69a
chain (217509): tree_root 28dc17c03924644b3da99ce8afbb434a9efb2312ff21b53bfeaeb38015dc51aa timestamp 1711286206 
chain (217510):   added to main chain
chain (217510):   new height: 217510
chain (217510): adding block: 000000000000000397ecdb973332595c777c69952591cd137745bf1c3c9e2898
chain (217510): tree_root 28dc17c03924644b3da99ce8afbb434a9efb2312ff21b53bfeaeb38015dc51aa timestamp 1711286661 
chain (217511):   added to main chain
chain (217511):   new height: 217511
chain (217511): adding block: 0000000000000002496db35faf8c3251d500653e00c2c4e378694b7b6bf40bc5
chain (217511): tree_root 28dc17c03924644b3da99ce8afbb434a9efb2312ff21b53bfeaeb38015dc51aa timestamp 1711287670 
chain (217512):   added to main chain
chain (217512):   new height: 217512
chain (217512): adding block: 0000000000000001c9d74d480aaaa425723ac559f3da551b31f4acbd1dfae0fd
chain (217512): tree_root 93648a8aa37e3501d713ce8336ff04e8ff19346f6be27099ab668b63f368c2e0 timestamp 1711287824 
chain (217513):   added to main chain
chain (217513):   new height: 217513
chain (217017): adding block: 00000000000000040e97f423c0216030c7582a2695adf67ed0f50277586d4245
chain (217017): tree_root 10974c25520a7507f2994566e7a1345d0b5eecb9fd2f1a3c4e77194b0166aa68 timestamp 1710991231 
chain (217018):   added to main chain
chain (217018):   new height: 217018
`
	reader, writer := io.Pipe()

	signalChannel := make(chan os.Signal, 1)
	slidingWindow := make([]BlockInfo, 0, BlocksToStore)
	go func() {
		defer writer.Close() // Ensure to close the writer to signal the end of input
		_, err := writer.Write([]byte(syncdata))
		if err != nil {
			log.Fatalf("Error writing to pipe: %v", err)
		}

		signalChannel <- syscall.SIGINT
	}()
	parseAndWriteOutput(reader, signalChannel, slidingWindow, "./test_sync_out")
}
