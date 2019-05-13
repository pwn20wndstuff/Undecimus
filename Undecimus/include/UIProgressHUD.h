#import <UIKit/UIKit.h>

@class UIProgressIndicator, UILabel, UIImageView, UIWindow;

@interface UIProgressHUD : UIView {

	UIProgressIndicator* _progressIndicator;
	UILabel* _progressMessage;
	UIImageView* _doneView;
	UIWindow* _parentWindow;
	struct {
		unsigned isShowing : 1;
		unsigned isShowingText : 1;
		unsigned fixedFrame : 1;
		unsigned reserved : 30;
	}  _progressHUDFlags;

}
-(id)initWithFrame:(CGRect)arg1 ;
-(void)layoutSubviews;
-(void)hide;
-(void)show:(bool)arg1 ;
-(void)drawRect:(CGRect)arg1 ;
-(void)dealloc;
-(void)setText:(id)arg1 ;
-(id)initWithWindow:(id)arg1 ;
-(void)done;
-(void)setFontSize:(int)arg1 ;
-(id)_progressIndicator;
-(void)setShowsText:(bool)arg1 ;
-(void)showInView:(id)arg1 ;
@end

