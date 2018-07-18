import React from 'react'
import './PortfolioItem.css'

class PortfolioItem extends React.Component {
    constructor(props) {
        super();
        this.props = props
    }

    redirect(url) {
        return () => {
            window.open(url, '_blank')
        }
    }

    render() {
        return (
            <div className={'portfolioItem'}>
                <div className={'portfolioProjectTitle'}>{this.props.name}</div>
                <div className={'portfolioProjectDescription'}>{this.props.description}</div>
                {!!this.props.github ? <div className={'portfolioExternalButton'} onClick={this.redirect(this.props.github)}>Github</div> : <div>&nbsp;</div>}
                {!!this.props.binder ? <div className={'portfolioExternalButton'} onClick={this.redirect(this.props.binder)}>Binder</div> : <div>&nbsp;</div>}
            </div>
        );
    }
}

export default PortfolioItem;