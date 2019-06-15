import React from 'react';
import styles from './PostTags.module.css'
import Skeleton from '../../../util/Skeleton/Skeleton';
import Tag from '../../../util/Tag/Tag';

class PostTags extends React.Component {
    genTagsBlock() {
        if (!this.props.tags) {
            return <Skeleton align={'center'} className={styles.skeleton}/>;
        }
        return this.props.tags && this.props.tags.map(e => (
            <Tag key={e.id} interactive={true} className={styles.item} minimal={true}>{e.name}</Tag>
        ));
    }

    render() {
        return (
            <div className={this.props.className}>
                {this.genTagsBlock()}
            </div>
        );
    }
}

export default PostTags;