
%hook HamburgerMenu 

- (void)loadInterstitial {

}

%end
typedef struct GADAdSize {
    CGSize size;
    NSUInteger flags;
} GADAdSize;


%hook AdBannerView

- (void)loadRequest:(id)arg1 {

}

%end

%hook PhoneScreenTeam

- (void)showInterstitial {

}
- (void)loadInterstitial {

}
%end


%hook PhoneScreenOrganization
- (void)showInterstitial {

}
- (void)loadInterstitial {

}


- (CGFloat)tableView:(UITableView*)tableView heightForRowAtIndexPath:(NSIndexPath*)indexPath {
	CGFloat height = %orig;
	if (height == 50) {
		return 0;
	}
	return height;
}

%end

%hook KrVideoPlayerController

- (void)requestAds {

}
- (void)adsLoader:(id)arg1 adsLoadedWithData:(id)arg2 {

}
- (void)setupAdsLoader {

}
%end



