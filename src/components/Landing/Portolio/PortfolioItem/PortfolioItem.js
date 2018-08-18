import React from 'react'
import styles from './PortfolioItem.module.css'

class PortfolioItem extends React.Component {
    constructor(props) {
        super(props);
    }

    redirect(url) {
        return () => {
            window.open(url, '_blank')
        }
    }

    render() {
        return (
            <div className={styles.portfolioItem}>
                <div className={styles.title}>{this.props.name}</div>
                <div className={styles.description}>{this.props.description}</div>
                <div className={styles.links}>
                    {this.props.github ? <div className={styles.github + ' ' + styles.portfolioExternalButton}
                                              onClick={this.redirect(this.props.github)}>Github</div> :
                        <div>&nbsp;</div>}
                    {this.props.binder ? <div className={styles.binder + ' ' + styles.portfolioExternalButton}
                                              onClick={this.redirect(this.props.binder)}>Binder</div> :
                        <div>&nbsp;</div>}
                </div>
            </div>
        );
    }
}

export default PortfolioItem;